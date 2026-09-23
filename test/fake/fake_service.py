#!/usr/bin/env python3
"""A fake duckdb-secrets/1 service and its identity provider, on one loopback port (specs/002).

Enough of both for the attach tests: the service's discovery and whoami, the IdP's discovery,
/authorize (auto-approves: 302 to the redirect_uri with a code and the state, PKCE checked at the
exchange), /token (authorization_code, refresh_token, client_credentials, the device code) and
/device. Plain http on 127.0.0.1 - the client allows that only with INSECURE_HTTP.

The service lives under a *realm* - the base path of the ATTACH - which picks its behaviour, since
a sqllogictest can only steer the fake through what it attaches:

    ''         the ordinary service: one issuer, /idp
    multi      two issuers (/idp and /idp2)
    wrong      speaks duckdb-secrets/2
    expiring   whoami accepts a token as first issued only twice, then answers 401 until the
               client renews it (a renewed token is accepted for good)
    revoking   like expiring, and its issuer (/idp-revoking) refuses every refresh: invalid_grant
    noflows    lists human_flows and service_flows, both empty: a client attempts no login at all
    broken     logs in and lists its secrets, but every material fetch answers 503: a lookup that picks
               one of them fails closed, and nothing else is disturbed
    nolist     logs in, but its secrets list answers 503: nothing to attach
    acting     the actor's service (specs/008, 009): the node's secrets (node_lake, shared_lake, and stats, whose
               comment counts exchanges, grants, revocations and live grants) and delegation grants - under a
               grant the node's own rights apply, for the grant's user; writes under a grant are refused
    shifty     like acting, but its discovery names another audience ("payroll-api") than the node's token has

Every realm serves the same secrets (SECRETS below) to every identity. A descriptor's comment counts
how often its material was fetched ("fetched N") - the only window a sqllogictest has into caching.

    fake_service.py --port-file PATH     # binds a free port and writes it to PATH
"""

import argparse
import base64
import hashlib
import json
import secrets
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOCK = threading.Lock()
TOKENS = {}    # access token -> {"identity": ..., "uses": n, "renewed": bool}
REFRESH = {}   # refresh token -> identity
CODES = {}     # authorization code -> (challenge, redirect_uri, identity)
DEVICES = {}   # device code -> pending polls left before approval

PERSON = {"subject": "alice", "roles": ["role:analysts", "group:sales"], "create": ["team_a_*"]}
SERVICE = {"subject": "client:etl", "roles": ["role:etl"], "create": True}
CLIENTS = {"etl": "s3cr3t"}
STATIC_TOKENS = {"static-token": {"subject": "client:static", "roles": [], "create": False}}
REALMS = {"", "multi", "wrong", "expiring", "revoking", "noflows", "broken", "nolist", "acting", "shifty"}
ISSUERS = {"idp", "idp2", "idp-revoking"}
FIRST_USES = 2  # expiring/revoking: how many whoami calls a token as first issued survives


SECRETS = {
    "crm_ro": {
        "type": "mssql", "scope": ["mssql://crm.corp.example"], "permissions": ["use", "annotate"],
        "params": {
            "host": "crm.corp.example",
            "user": "crm_reader",
            "password": {"type": "VARCHAR", "value": "p@ss-word"},
            "port": {"type": "INTEGER", "value": 1433},
            "encrypt": {"type": "BOOLEAN", "value": True},
            "extra_http_headers": {"type": "MAP(VARCHAR, VARCHAR)", "value": {"X-Tenant": "sales"}},
            "limits": {"type": "STRUCT(max_rows BIGINT, ratio DOUBLE)", "value": {"max_rows": 1000, "ratio": 0.5}},
            "replicas": {"type": "VARCHAR[]", "value": ["crm-a", "crm-b"]},
            "big": {"type": "HUGEINT", "value": 123456789012345678901234567890},
            "amount": {"type": "DECIMAL(38,2)", "value": "12345678901234567890.12"},
        },
        "redact_keys": ["password"],
    },
    "lake": {
        "type": "s3", "scope": ["s3://lake"], "permissions": ["use"],
        "params": {"key_id": "AKIA-LAKE", "secret": {"type": "VARCHAR", "value": "hunter2"}, "region": "eu-west-1"},
        "redact_keys": ["secret"],
    },
    "lake_team_a": {
        "type": "s3", "scope": ["s3://lake/team-a"], "permissions": ["use"],
        "params": {"key_id": "AKIA-TEAM-A", "secret": {"type": "VARCHAR", "value": "x"}},
        "redact_keys": ["secret"],
    },
    "seen_not_used": {
        "type": "s3", "scope": ["s3://lake/restricted"], "permissions": ["annotate"],
        "params": {"key_id": "NEVER"}, "redact_keys": [],
    },
    "dyn": {  # expires 20 s after each fetch: served from the cache for half of that
        "type": "s3", "scope": ["s3://dyn"], "permissions": ["use"], "dynamic": True, "lifetime": 20,
        "params": {"key_id": "DYN"}, "redact_keys": [],
    },
    "dyn_expired": {  # already expired when served: never reused
        "type": "s3", "scope": ["s3://dyn-expired"], "permissions": ["use"], "dynamic": True, "lifetime": -60,
        "params": {"key_id": "DYN"}, "redact_keys": [],
    },
    # a login a service must never be able to plant: it covers every loopback ATTACH
    "planted": {
        "type": "tresor", "scope": ["tresor:127.0.0.1"], "permissions": ["use"],
        "params": {"flow": "token", "token": "planted-token"}, "redact_keys": ["token"],
    },
    "bare_number": {
        "type": "mssql", "scope": ["mssql://bare"], "permissions": ["use"],
        "params": {"port": 1433}, "redact_keys": [],
    },
    # a dynamic s3 secret for the REFRESH auto path (specs/006): each mint is a new key valid for 600 s (so the
    # client caches it), the endpoint is this fake's S3, which refuses the first mint; its comment counts the
    # writes the service received for it
    "dyn_s3": {
        "type": "s3", "scope": ["s3://dynbucket"], "owner": "role:other", "permissions": ["use"], "dynamic": True,
        "lifetime": 600, "params": {"key_id": "DYN-S3"}, "redact_keys": ["secret"],
    },
    # a static s3 secret someone stored with httpfs's refresh recipe: the client must drop it
    "static_with_refresh": {
        "type": "s3", "scope": ["s3://staticbucket"], "owner": "role:other", "permissions": ["use"],
        "params": {"key_id": "STATIC", "refresh": "auto",
                   "refresh_info": {"type": "STRUCT(key_id VARCHAR)", "value": {"key_id": "STATIC"}}},
        "redact_keys": [],
    },
    # a name another tool gave, in mixed case: the service compares names exactly
    "Mixed_Case": {
        "type": "http", "scope": ["https://mixed.example"], "owner": "role:other",
        "permissions": ["use", "update", "delete", "annotate", "grant"],
        "params": {"bearer_token": "m"}, "redact_keys": ["bearer_token"],
    },
    "bad_value": {
        "type": "mssql", "scope": ["mssql://bad"], "permissions": ["use"],
        "params": {"port": {"type": "INTEGER", "value": "not-a-number"}}, "redact_keys": [],
    },
}
FETCHED = {}  # secret name -> material fetches
WRITES = {}  # secret name -> PUT / DELETE / PATCH the service received for it

# --- acting for acl sessions (specs/008) ---------------------------------------------------------------
# tokens an acl node received from its users: meant for the node (never accepted by the service), exchanged
# at the IdP by the etl client for tokens meant for the service
NODE_TOKENS = {
    "node-token-alice": {"subject": "alice", "roles": ["role:analysts"], "create": []},
    "node-token-carol": {"subject": "carol", "roles": ["role:interns"], "create": []},  # the grant is refused
    "node-token-erin": {"subject": "erin", "roles": ["role:analysts"], "create": []},  # a grant living 1 s
    "node-token-slow": {"subject": "alice", "roles": ["role:analysts"], "create": []},  # exchanged after 3 s
    "node-token-mallory": {"subject": "mallory", "roles": [], "create": []},  # exchanged for payroll-api
}
REFUSED_NODE_TOKEN = "node-token-dave"  # the IdP refuses to exchange it
GRANTS = {}  # grant id -> {"actor": subject, "user": identity, "expires": epoch}
STATS = {"exchanges": 0, "grants": 0, "revoked": 0}


def descriptor(name, sec):
    # a written secret carries its own comment and version; the seeded ones count their material fetches
    return {
        "name": name, "type": sec["type"], "provider": sec.get("provider", "config"), "scope": sec["scope"],
        "comment": sec["comment"] if "comment" in sec else (
            "writes %d" % WRITES.get(name, 0) if name == "dyn_s3" else "fetched %d" % FETCHED.get(name, 0)),
        "owner": sec.get("owner", "role:admins"),
        "created_at": "2026-09-01T10:00:00Z", "updated_at": "2026-09-10T08:30:00Z",
        "version": str(sec.get("version", 7)),
        "dynamic": sec.get("dynamic", False), "permissions": sec["permissions"],
    }


def s256(verifier):
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


def jwt_shaped(aud):
    """An unsigned JWT-shaped access token: the fake checks tokens by lookup, the client reads `aud` (specs/008)."""
    part = lambda obj: base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()
    return part({"alg": "none"}) + "." + part({"aud": aud, "jti": secrets.token_urlsafe(9)}) + ".x"


def issue(identity, with_refresh, renewed=False, aud="duckdb-secrets"):
    token = jwt_shaped(aud)
    TOKENS[token] = {"identity": identity, "uses": 0, "renewed": renewed}
    body = {"access_token": token, "token_type": "Bearer", "expires_in": 300}
    if with_refresh:
        refresh = "rt-" + secrets.token_urlsafe(12)
        REFRESH[refresh] = identity
        body["refresh_token"] = refresh
    return body


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def base(self):
        return "http://127.0.0.1:%d" % self.server.server_address[1]

    def send(self, status, body, content_type="application/json", headers=None):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def problem(self, status, kind, detail):
        self.send(status, {"type": kind, "title": kind, "detail": detail}, "application/problem+json")

    def form(self):
        length = int(self.headers.get("Content-Length") or 0)
        return {k: v[0] for k, v in urllib.parse.parse_qs(self.rfile.read(length).decode()).items()}

    @staticmethod
    def split(path):
        """'/<realm>/rest' -> (realm, '/rest'); the root realm is ''."""
        parts = path.split("/", 2)
        if len(parts) > 1 and parts[1] in REALMS | ISSUERS:
            return parts[1], "/" + (parts[2] if len(parts) > 2 else "")
        return "", path

    # --- a minimal S3 (specs/006): /dynbucket/<key>, refusing dyn_s3's first mint (DYN-S3-1) -------------
    S3_OBJECT = b"hello from s3\n"

    def s3(self, head):
        auth = self.headers.get("Authorization", "")
        key_id = auth.split("Credential=")[1].split("/")[0] if "Credential=" in auth else ""
        if not key_id or key_id == "DYN-S3-1":
            body = b"<Error><Code>AccessDenied</Code><Message>expired</Message></Error>"
            self.send_response(403)
            self.send_header("Content-Type", "application/xml")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if not head:
                self.wfile.write(body)
            return
        data = self.S3_OBJECT
        status, start, end = 200, 0, len(data) - 1
        rng = self.headers.get("Range", "")
        if rng.startswith("bytes="):
            first, _, last = rng[len("bytes="):].partition("-")
            start, end = int(first or 0), min(int(last) if last else len(data) - 1, len(data) - 1)
            status = 206
        chunk = data[start:end + 1]
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(chunk) if not head else len(data)))
        self.send_header("Last-Modified", "Wed, 01 Jan 2026 00:00:00 GMT")
        self.send_header("ETag", '"s3-object"')
        if status == 206:
            self.send_header("Content-Range", "bytes %d-%d/%d" % (start, end, len(data)))
        self.end_headers()
        if not head:
            self.wfile.write(chunk)

    def do_HEAD(self):
        if urllib.parse.urlparse(self.path).path.startswith("/dynbucket/"):
            self.s3(True)
            return
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        if url.path.startswith("/dynbucket/"):
            self.s3(False)
            return
        query = {k: v[0] for k, v in urllib.parse.parse_qs(url.query).items()}
        base = self.base()
        realm, rest = self.split(url.path)

        if realm in ISSUERS:
            if rest == "/.well-known/openid-configuration":
                self.send(200, {
                    "issuer": base + "/" + realm,
                    "authorization_endpoint": base + "/" + realm + "/authorize",
                    "token_endpoint": base + "/" + realm + "/token",
                    "device_authorization_endpoint": base + "/" + realm + "/device",
                })
            elif rest == "/authorize":
                if query.get("client_id") != "duckdb" or query.get("code_challenge_method") != "S256":
                    self.send(400, {"error": "invalid_request"})
                    return
                code = "code-" + secrets.token_urlsafe(8)
                with LOCK:
                    CODES[code] = (query.get("code_challenge"), query.get("redirect_uri"), PERSON)
                target = query["redirect_uri"] + "?" + urllib.parse.urlencode(
                    {"code": code, "state": query.get("state", "")})
                self.send(302, b"", "text/plain", {"Location": target})
            else:
                self.send(404, {"error": "not_found"})
            return

        prefix = base + ("/" + realm if realm else "")
        if rest == "/.well-known/duckdb-secrets":
            issuer = {
                "issuer": base + ("/idp-revoking" if realm == "revoking" else "/idp"),
                "client_id": "duckdb",
                "scopes": ["openid", "offline_access", "duckdb-secrets"],
                "audience": "payroll-api" if realm == "shifty" else "duckdb-secrets",
                "human_flows": ["authorization_code", "device_code"],
                "service_flows": ["client_credentials"],
            }
            if realm == "noflows":
                issuer = dict(issuer, human_flows=[], service_flows=[])
            issuers = [issuer] + ([dict(issuer, issuer=base + "/idp2")] if realm == "multi" else [])
            self.send(200, {
                "protocol": "duckdb-secrets/2" if realm == "wrong" else "duckdb-secrets/1",
                "api": prefix,
                "issuers": issuers,
                # delegation is offered everywhere but the expiring realm (specs/007: the client checks it)
                "capabilities": {"write": True, "annotate": True, "dynamic": True,
                                 "delegation": realm != "expiring"},
            })
            return
        if realm in ("acting", "shifty") and rest.startswith("/v1/"):
            self.acting_get(rest)
            return
        if rest == "/v1/whoami":
            auth = self.headers.get("Authorization", "")
            token = auth[len("Bearer "):] if auth.startswith("Bearer ") else ""
            with LOCK:
                entry = TOKENS.get(token)
                identity = entry["identity"] if entry else STATIC_TOKENS.get(token)
                if entry:
                    entry["uses"] += 1
                    if realm in ("expiring", "revoking") and not entry["renewed"] and entry["uses"] > FIRST_USES:
                        identity = None
            if identity is None:
                self.problem(401, "unauthenticated", "token missing, invalid or expired")
                return
            self.send(200, {
                "issuer": base + ("/idp-revoking" if realm == "revoking" else "/idp"),
                "subject": identity["subject"],
                "roles": identity["roles"],
                "actor": None,
                "expires_at": "2030-01-01T00:00:00Z",
                "permissions": {"create": identity["create"]},
            })
            return
        if rest == "/v1/secrets" or rest.startswith("/v1/secrets/"):
            auth = self.headers.get("Authorization", "")
            token = auth[len("Bearer "):] if auth.startswith("Bearer ") else ""
            with LOCK:
                known = token in TOKENS or token in STATIC_TOKENS
            if not known:
                self.problem(401, "unauthenticated", "token missing, invalid or expired")
                return
            if realm == "nolist" or (realm == "broken" and rest != "/v1/secrets"):
                self.problem(503, "service_unavailable", "the store is down")
                return
            if rest == "/v1/secrets":
                with LOCK:
                    self.send(200, [descriptor(n, s) for n, s in SECRETS.items()])
                return
            if rest.endswith("/grants"):
                sec = SECRETS.get(urllib.parse.unquote(rest[len("/v1/secrets/"):-len("/grants")]))
                if sec is None:
                    self.problem(404, "not_found", "no secret")
                    return
                with LOCK:
                    self.send(200, list(sec.get("grants", {}).values()))
                return
            name = urllib.parse.unquote(rest[len("/v1/secrets/"):])
            sec = SECRETS.get(name)
            if sec is None:
                self.problem(404, "not_found", "no secret %s" % name)
                return
            if "use" not in sec["permissions"]:
                self.problem(403, "no_verb", "the caller's roles do not hold use")
                return
            with LOCK:
                FETCHED[name] = FETCHED.get(name, 0) + 1
                body = dict(descriptor(name, sec), params=dict(sec["params"]), redact_keys=sec["redact_keys"],
                            expires_at=None)
                if name == "dyn_s3":
                    body["params"].update({
                        "key_id": "DYN-S3-%d" % FETCHED[name], "secret": {"type": "VARCHAR", "value": "s"},
                        "region": "us-east-1", "endpoint": "127.0.0.1:%d" % self.server.server_address[1],
                        "url_style": "path", "use_ssl": {"type": "BOOLEAN", "value": False}})
                    body["expires_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                                       time.gmtime(time.time() + sec["lifetime"]))
                elif sec.get("dynamic"):
                    body["params"]["key_id"] = "DYN-%d" % FETCHED[name]
                    body["expires_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                                       time.gmtime(time.time() + sec["lifetime"]))
            self.send(200, body)
            return
        self.send(404, {"type": "not_found"})

    # --- acting (specs/008): grants, the Delegation header ---------------------------------------------
    def bearer_identity(self):
        auth = self.headers.get("Authorization", "")
        token = auth[len("Bearer "):] if auth.startswith("Bearer ") else ""
        with LOCK:
            entry = TOKENS.get(token)
        return entry["identity"] if entry else None

    def effective(self):
        """(identity the service answers as, actor subject or None); (None, None) after a 401 was sent."""
        caller = self.bearer_identity()
        if caller is None:
            self.problem(401, "unauthenticated", "token missing, invalid or expired")
            return None, None
        grant_id = self.headers.get("Delegation")
        if not grant_id:
            return caller, None
        with LOCK:
            grant = GRANTS.get(grant_id)
            alive = grant and grant["expires"] > time.time() and grant["actor"] == caller["subject"]
        if not alive:
            self.problem(401, "unauthenticated", "the delegation grant is not valid for this actor")
            return None, None
        return grant["user"], caller["subject"]

    def acting_get(self, rest):
        identity, actor = self.effective()
        if identity is None:
            return
        if rest == "/v1/whoami":
            self.send(200, {"issuer": self.base() + "/idp", "subject": identity["subject"], "roles": identity["roles"],
                            "actor": actor, "expires_at": "2030-01-01T00:00:00Z",
                            "permissions": {"create": identity["create"]}})
            return
        # the node's own secrets - under a grant too (specs/009): a grant acts with the actor's rights, for its user
        with LOCK:
            stats = "exchanges %d grants %d revoked %d live %d" % (
                STATS["exchanges"], STATS["grants"], STATS["revoked"], len(GRANTS))
        listing = {
            "node_lake": {"type": "s3", "scope": ["s3://acting"], "permissions": ["use"],
                          "params": {"key_id": "NODE"}, "redact_keys": []},
            "shared_lake": {"type": "s3", "scope": ["s3://shared"], "permissions": ["use"],
                            "params": {"key_id": "NODE-SHARED"}, "redact_keys": []},
            "stats": {"type": "http", "scope": ["https://stats.invalid"], "permissions": [], "comment": stats,
                      "params": {}, "redact_keys": []},
        }
        if rest == "/v1/secrets":
            self.send(200, [descriptor(n, sec) for n, sec in listing.items()])
            return
        if rest.endswith("/grants"):  # managing grants is an admin's; nothing is managed through the node here
            if actor:
                self.problem(403, "actor_not_allowed", "this server may not grant for users")
            else:
                self.send(200, [])
            return
        name = urllib.parse.unquote(rest[len("/v1/secrets/"):]) if rest.startswith("/v1/secrets/") else None
        if name not in listing or "use" not in listing[name]["permissions"]:
            self.problem(404, "not_found", "no secret")
            return
        sec = listing[name]
        self.send(200, dict(descriptor(name, sec), params=sec["params"], redact_keys=[], expires_at=None))

    def acting_post_grant(self):
        caller = self.bearer_identity()
        if caller is None:
            self.problem(401, "unauthenticated", "token missing, invalid or expired")
            return
        if not caller["subject"].startswith("client:"):
            self.problem(403, "actor_not_allowed", "only a service acts for users")
            return
        body = self.body()
        with LOCK:
            entry = TOKENS.get(body.get("subject_token", ""))
        user = entry["identity"] if entry else None
        if user is None or user["subject"].startswith("client:"):
            self.problem(401, "unauthenticated", "the subject token is not a user's token for this service")
            return
        if user["subject"] == "carol":
            self.problem(403, "actor_not_allowed", "this actor may not act for carol")
            return
        ttl = 1 if user["subject"] == "erin" else min(int(body.get("ttl") or 3600), 8 * 3600)
        grant_id = "dg-" + secrets.token_urlsafe(12)
        expires = time.time() + ttl
        with LOCK:
            GRANTS[grant_id] = {"actor": caller["subject"], "user": user, "expires": expires}
            STATS["grants"] += 1
        # erin's grant claims an hour but the service drops it after a second: the client learns it from a 401
        shown = expires + 3600 if user["subject"] == "erin" else expires
        self.send(201, {"id": grant_id, "subject": user["subject"], "actor": caller["subject"],
                        "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(shown))})

    def acting_delete_grant(self, grant_id):
        caller = self.bearer_identity()
        if caller is None:
            self.problem(401, "unauthenticated", "token missing, invalid or expired")
            return
        with LOCK:
            grant = GRANTS.get(grant_id)
            if grant is None or grant["actor"] != caller["subject"]:
                self.problem(404, "not_found", "no such grant")
                return
            del GRANTS[grant_id]
            STATS["revoked"] += 1
        self.send(204, b"", "text/plain")

    # --- writes (specs/005): any realm, any authenticated caller; names starting forbidden_ are refused ---
    def authorised(self):
        auth = self.headers.get("Authorization", "")
        token = auth[len("Bearer "):] if auth.startswith("Bearer ") else ""
        with LOCK:
            if token in TOKENS or token in STATIC_TOKENS:
                return True
        self.problem(401, "unauthenticated", "token missing, invalid or expired")
        return False

    def body(self):
        length = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(length) or b"null")

    def refuse_delegated_write(self, realm):
        """acting: a write carrying a grant is the actor policy's refusal (as the reference server's default)."""
        if realm not in ("acting", "shifty") or not self.headers.get("Delegation"):
            return False
        identity, actor = self.effective()
        if identity is not None:
            self.problem(403, "actor_not_allowed", "this actor may not write for users")
        return True

    def do_PUT(self):
        realm, rest = self.split(urllib.parse.urlparse(self.path).path)
        if self.refuse_delegated_write(realm):
            return
        if not rest.startswith("/v1/secrets/") or not self.authorised():
            if rest.startswith("/v1/secrets/"):
                return
            self.send(404, {"type": "not_found"})
            return
        parts = [urllib.parse.unquote(p) for p in rest[len("/v1/secrets/"):].split("/")]
        body = self.body()
        with LOCK:
            WRITES[parts[0]] = WRITES.get(parts[0], 0) + 1
            if len(parts) == 3 and parts[1] == "grants":
                sec = SECRETS.get(parts[0])
                if sec is None:
                    self.problem(404, "not_found", "no secret")
                    return
                grants = sec.setdefault("grants", {})
                grants[parts[2]] = {"id": parts[2], "principal": body["principal"], "verbs": body["verbs"]}
                self.send(200, list(grants.values()))
                return
            name = parts[0]
            if name.startswith("forbidden_"):
                self.problem(403, "no_verb", "the caller may not create this secret")
                return
            params = body.get("params", {})
            if any(v is None or (isinstance(v, dict) and v.get("value") is None) for v in params.values()):
                self.problem(422, "invalid_secret", "a parameter is null")  # as the reference server
                return
            if any(k not in params for k in body.get("redact_keys", [])):
                self.problem(422, "invalid_secret", "a redact key is not a parameter")  # as the reference server
                return
            exists = name in SECRETS
            if exists and self.headers.get("If-None-Match") == "*":
                self.problem(412, "precondition_failed", "the secret exists")
                return
            old = SECRETS.get(name, {})
            SECRETS[name] = {
                "type": body["type"], "provider": body.get("provider") or "config", "scope": body.get("scope", []),
                "permissions": ["use", "update", "delete", "annotate", "grant"],
                "params": body.get("params", {}), "redact_keys": body.get("redact_keys", []),
                "comment": old.get("comment", ""), "owner": "client:etl",
                "version": old.get("version", 0) + 1, "grants": old.get("grants", {}),
            }
            self.send(200 if exists else 201, descriptor(name, SECRETS[name]))

    def do_DELETE(self):
        realm, rest = self.split(urllib.parse.urlparse(self.path).path)
        if realm in ("acting", "shifty") and rest.startswith("/v1/delegations/"):
            self.acting_delete_grant(urllib.parse.unquote(rest[len("/v1/delegations/"):]))
            return
        if self.refuse_delegated_write(realm):
            return
        if not rest.startswith("/v1/secrets/"):
            self.send(404, {"type": "not_found"})
            return
        if not self.authorised():
            return
        parts = [urllib.parse.unquote(p) for p in rest[len("/v1/secrets/"):].split("/")]
        with LOCK:
            sec = SECRETS.get(parts[0])
            if sec is None or (len(parts) == 3 and parts[2] not in sec.get("grants", {})):
                self.problem(404, "not_found", "no such secret or grant")
                return
            if parts[0].startswith("protected_"):
                self.problem(403, "no_verb", "the caller's roles do not hold delete")
                return
            WRITES[parts[0]] = WRITES.get(parts[0], 0) + 1
            if len(parts) == 3:
                del sec["grants"][parts[2]]
            else:
                del SECRETS[parts[0]]
        self.send(204, b"", "text/plain")

    def do_PATCH(self):
        realm, rest = self.split(urllib.parse.urlparse(self.path).path)
        if self.refuse_delegated_write(realm):
            return
        if not rest.startswith("/v1/secrets/"):
            self.send(404, {"type": "not_found"})
            return
        if not self.authorised():
            return
        name = urllib.parse.unquote(rest[len("/v1/secrets/"):])
        body = self.body()
        with LOCK:
            WRITES[name] = WRITES.get(name, 0) + 1
            sec = SECRETS.get(name)
            if sec is None:
                self.problem(404, "not_found", "no secret")
                return
            sec["comment"] = body["comment"]
            sec["version"] = int(sec.get("version", 7)) + 1
            self.send(200, descriptor(name, sec))

    def do_POST(self):
        url = urllib.parse.urlparse(self.path)
        realm, rest = self.split(url.path)
        if realm in ("acting", "shifty") and rest == "/v1/delegations":
            self.acting_post_grant()
            return
        if rest.startswith("/v1/secrets/") and self.refuse_delegated_write(realm):
            return
        form = self.form()
        if realm not in ISSUERS:
            self.send(404, {"type": "not_found"})
            return
        if rest == "/device":
            code = "dev-" + secrets.token_urlsafe(8)
            with LOCK:
                DEVICES[code] = 1  # one authorization_pending, then approved
            self.send(200, {
                "device_code": code, "user_code": "ABCD-EFGH",
                "verification_uri": self.base() + "/" + realm + "/activate", "interval": 1, "expires_in": 60,
            })
            return
        if rest != "/token":
            self.send(404, {"error": "not_found"})
            return
        grant = form.get("grant_type")
        if grant == "urn:ietf:params:oauth:grant-type:token-exchange" and form.get("subject_token") == "node-token-slow":
            time.sleep(3)  # outside the lock: the fake keeps answering everyone else
        with LOCK:
            if grant == "authorization_code":
                entry = CODES.pop(form.get("code"), None)
                if not entry or entry[1] != form.get("redirect_uri"):
                    self.send(400, {"error": "invalid_grant", "error_description": "unknown code"})
                elif s256(form.get("code_verifier", "")) != entry[0]:
                    self.send(400, {"error": "invalid_grant", "error_description": "PKCE verification failed"})
                else:
                    self.send(200, issue(entry[2], True))
            elif grant == "refresh_token":
                identity = REFRESH.get(form.get("refresh_token"))
                if identity is None or realm == "idp-revoking":
                    self.send(400, {"error": "invalid_grant", "error_description": "refresh token revoked"})
                else:
                    self.send(200, issue(identity, False, renewed=True))  # no rotation: keep the old one
            elif grant == "client_credentials":
                if CLIENTS.get(form.get("client_id")) != form.get("client_secret"):
                    self.send(401, {"error": "invalid_client", "error_description": "bad client secret"})
                else:
                    self.send(200, issue(SERVICE, False))
            elif grant == "urn:ietf:params:oauth:grant-type:token-exchange":
                at = "urn:ietf:params:oauth:token-type:access_token"
                subject = form.get("subject_token")
                if CLIENTS.get(form.get("client_id")) != form.get("client_secret"):
                    self.send(401, {"error": "invalid_client", "error_description": "bad client secret"})
                elif form.get("audience") != "duckdb-secrets" or form.get("subject_token_type") != at:
                    self.send(400, {"error": "invalid_target", "error_description": "not an audience of this IdP"})
                elif subject not in NODE_TOKENS:
                    self.send(400, {"error": "invalid_grant",
                                    "error_description": "the subject token %s is not valid" % subject})
                else:
                    STATS["exchanges"] += 1
                    aud = "payroll-api" if subject == "node-token-mallory" else "duckdb-secrets"
                    self.send(200, dict(issue(NODE_TOKENS[subject], False, aud=aud), issued_token_type=at))
            elif grant == "urn:ietf:params:oauth:grant-type:device_code":
                code = form.get("device_code")
                if code not in DEVICES:
                    self.send(400, {"error": "access_denied"})
                elif DEVICES[code] > 0:
                    DEVICES[code] -= 1
                    self.send(400, {"error": "authorization_pending"})
                else:
                    del DEVICES[code]
                    self.send(200, issue(PERSON, True))
            else:
                self.send(400, {"error": "unsupported_grant_type"})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port-file", required=True)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    with open(args.port_file, "w") as f:
        f.write(str(server.server_address[1]))
    server.serve_forever()


if __name__ == "__main__":
    main()
