#!/usr/bin/env python3
"""The SPIFFE spike's console (tresor specs/046): runs each step of a node's SPIFFE login and shows what happened.

A local page (http://127.0.0.1:18455) with the architecture and a Run button. Each step is one thing the spike
wants to learn - does Keycloak take a JWT-SVID as jwt-spiffe, as jwt-bearer (what tresor sends today), does
tresor log in with it, is another workload's SVID refused - and its result is the claims and answers that show
it. Never a token: an SVID or an access token is decoded to its claims here and dropped; anything token-shaped in
a command's output is masked before it reaches the page.

Started by spike.sh console, which sets SPIKE_ISSUER, SPIKE_SERVICE, SPIKE_TRUST_DOMAIN, TRESOR_DUCKDB and
TRESOR_EXTENSION. Standard library only, as test/fake.
"""

from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import asdict, dataclass, replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Literal

HERE = Path(__file__).resolve().parent
RUN = HERE / "run"
PORT = int(os.getenv("SPIKE_CONSOLE_PORT", "18455"))
OIDC = f"http://127.0.0.1:{os.getenv('SPIRE_OIDC_PORT', '18456')}"
COMPOSE = ["docker", "compose", "-p", "tresor-spiffe", "-f", str(HERE / "docker-compose.yml")]
AGENT_SOCKET = "/run/spire/sockets/agent/api.sock"
JWT_SHAPED = re.compile(r"eyJ[A-Za-z0-9._-]*")
ANSI = re.compile(r"\x1b\[[0-9;]*m")
ASSERTION_TYPES = {
    "jwt-spiffe": "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe",
    "jwt-bearer": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
}

Status = Literal["running", "ok", "expected", "finding", "failed"]


@dataclass(frozen=True)
class Config:
    issuer: str
    service: str
    trust_domain: str
    duckdb: str
    extension: str

    @property
    def node_id(self) -> str:
        return f"{self.trust_domain}/node/acl-node"

    @property
    def intruder_id(self) -> str:
        return f"{self.trust_domain}/node/intruder"

    @property
    def host(self) -> str:
        return re.sub(r"^https?://", "", self.service)


@dataclass(frozen=True)
class Step:
    id: str
    title: str
    status: Status
    facts: tuple[tuple[str, str], ...] = ()
    note: str = ""


class SpikeError(Exception):
    """A step could not be run at all (a service down, a command missing) - its message holds no token."""


# --- pure helpers ---------------------------------------------------------------------------------------------


def masked(text: str) -> str:
    return JWT_SHAPED.sub("<token>", ANSI.sub("", text))


def claims(jwt: str) -> tuple[dict, dict]:
    """The header and the claims of a JWT, unverified - for showing, never for deciding."""

    def part(segment: str) -> dict:
        return json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))

    match jwt.split("."):
        case [header, payload, _]:
            return part(header), part(payload)
        case _:
            raise SpikeError("not a JWT")


def when(epoch: object) -> str:
    match epoch:
        case int() | float():
            left = int(epoch - time.time())
            stamp = time.strftime("%H:%M:%S", time.localtime(epoch))
            return f"{stamp} ({left:+d} s)"
        case _:
            return "absent"


def svid_facts(jwt: str) -> tuple[tuple[str, str], ...]:
    header, body = claims(jwt)
    return (
        ("sub", body.get("sub", "absent")),
        ("aud", ", ".join(body.get("aud", [])) if isinstance(body.get("aud"), list) else str(body.get("aud"))),
        ("exp", when(body.get("exp"))),
        ("iss", body.get("iss", "absent (as Keycloak's SPIFFE authentication wants)")),
        ("jti", "present" if "jti" in body else "absent"),
        ("alg / kid", f"{header.get('alg')} / {header.get('kid', '-')}"),
    )


def access_facts(jwt: str) -> tuple[tuple[str, str], ...]:
    _, body = claims(jwt)
    aud = body.get("aud")
    return (
        ("iss", body.get("iss", "-")),
        ("azp / client_id", f"{body.get('azp', '-')} / {body.get('client_id', '-')}"),
        ("aud", ", ".join(aud) if isinstance(aud, list) else str(aud)),
        ("roles", ", ".join(body.get("realm_access", {}).get("roles", []))),
        ("exp", when(body.get("exp"))),
    )


def tresor_facts(output: str) -> tuple[tuple[str, str], ...]:
    """The key=value lines the node scripts print, and the first error, from the CLI's (masked) output."""

    def fact(line: str) -> tuple[str, str] | None:
        match line.split("=", 1):
            case [("tresor" | "login" | "secrets" | "audit") as key, value]:
                return key, value
            case _ if "Error" in line:
                return "error", line
            case _:
                return None

    return tuple(f for f in map(fact, (line.strip() for line in output.splitlines())) if f)


# --- I/O at the edges -----------------------------------------------------------------------------------------


def http(method: str, url: str, form: dict | None = None, body: dict | None = None, headers: dict | None = None):
    data = (
        urllib.parse.urlencode(form).encode()
        if form is not None
        else json.dumps(body).encode()
        if body is not None
        else None
    )
    content = {"Content-Type": "application/x-www-form-urlencoded"} if form is not None else {}
    content |= {"Content-Type": "application/json"} if body is not None else {}
    request = urllib.request.Request(url, data=data, method=method, headers=content | (headers or {}))
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as error:
        raw = error.read()
        try:
            return error.code, json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            return error.code, {"detail": masked(raw.decode(errors="replace"))[:200]}
    except (urllib.error.URLError, TimeoutError) as error:
        raise SpikeError(f"{url} is not reachable: {error}") from None


def fetch_svid(spiffe_id: str, audience: str) -> str:
    """A fresh JWT-SVID from the SPIRE agent's Workload API, as spiffe-helper would write it."""
    command = COMPOSE + [
        "exec", "-T", "spire-agent", "/opt/spire/bin/spire-agent", "api", "fetch", "jwt",
        "-audience", audience, "-spiffeID", spiffe_id, "-socketPath", AGENT_SOCKET,
    ]  # fmt: skip
    done = subprocess.run(command, check=False, capture_output=True, text=True, timeout=60)
    lines = [line.strip() for line in done.stdout.splitlines()]
    tokens = [lines[i + 1] for i, line in enumerate(lines[:-1]) if line.startswith("token(")]
    if done.returncode != 0 or not tokens:
        raise SpikeError(f"no SVID for {spiffe_id}: {masked(done.stderr or done.stdout).strip()[:300]}")
    return tokens[0]


def write_svid(name: str, jwt: str) -> Path:
    path = RUN / "svid" / f"{name}.jwt"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(jwt)
    path.chmod(0o600)
    return path


def token_request(cfg: Config, client_id: str, assertion: str, kind: str) -> tuple[int, dict]:
    return http(
        "POST",
        f"{cfg.issuer}/protocol/openid-connect/token",
        form={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_assertion_type": ASSERTION_TYPES[kind],
            "client_assertion": assertion,
        },
    )


def run_tresor(cfg: Config, script: str, svid: Path) -> str:
    for file in (cfg.duckdb, cfg.extension):
        if not Path(file).is_file():
            raise SpikeError(f"no {file} - build tresor (GEN=ninja make) or set TRESOR_DUCKDB / TRESOR_EXTENSION")
    env = os.environ | {
        "SPIKE_HOST": cfg.host,
        "SPIKE_ISSUER": cfg.issuer,
        "SPIKE_SVID_FILE": str(svid),
        "SPIKE_SPIFFE_ID": cfg.node_id,
        "TRESOR_KEYCHAIN": "memory",
    }
    command = [
        cfg.duckdb, "-no-agent", "-unsigned", "-no-init", "-list", "-noheader",
        "-cmd", f"SET autoinstall_known_extensions = false; LOAD '{cfg.extension}';",
        "-f", str(HERE / script), ":memory:",
    ]  # fmt: skip
    done = subprocess.run(command, check=False, capture_output=True, text=True, timeout=120, env=env)
    return masked(done.stdout + "\n" + done.stderr)


def spiffe_feature(info: dict) -> str | None:
    """Keycloak's SPIFFE feature from its server info: 'enabled (PREVIEW)', 'disabled', or None if it has none."""
    found = [f for f in info.get("features", []) if "spiffe" in str(f.get("name", "")).lower()]
    profile = info.get("profileInfo", {})  # older server info lists features by state
    match found, profile:
        case [feature, *_], _:
            return f"{'enabled' if feature.get('enabled') else 'disabled'} ({feature.get('type', '-')})"
        case [], {"disabledFeatures": [*disabled]} if any("spiffe" in str(f).lower() for f in disabled):
            return "disabled"
        case [], {"previewFeatures": [*preview]} if any("spiffe" in str(f).lower() for f in preview):
            return "enabled (PREVIEW)"
        case _:
            return None


# --- the steps --------------------------------------------------------------------------------------------------


def step_available(cfg: Config) -> Step:
    """Keycloak's own SPIFFE support - the route specs/046 takes where it is available."""
    base = cfg.issuer.split("/realms/")[0]
    realm = cfg.issuer.rsplit("/", 1)[1]
    status, answer = http(
        "POST",
        f"{base}/realms/master/protocol/openid-connect/token",
        form={"grant_type": "password", "client_id": "admin-cli", "username": "admin", "password": "admin"},
    )
    if status != 200:
        return Step("available", "", "failed", (("Keycloak admin login", f"status {status}"),))
    auth = {"Authorization": f"Bearer {answer['access_token']}"}
    _, info = http("GET", f"{base}/admin/serverinfo", headers=auth)
    _, providers = http("GET", f"{base}/admin/realms/{realm}/identity-provider/instances", headers=auth)
    spiffe = [p for p in providers if p.get("providerId") == "spiffe"] if isinstance(providers, list) else []
    feature = spiffe_feature(info)
    version = info.get("systemInfo", {}).get("version", "-")
    facts = (
        ("Keycloak", version),
        ("feature spiffe", feature or "unknown to this Keycloak"),
        (
            f"realm {realm}: IdP of type spiffe",
            ", ".join(f"{p.get('alias')} ({p.get('config', {}).get('trustDomain', '-')})" for p in spiffe) or "none",
        ),
    )
    if spiffe and (feature or "").startswith("enabled"):
        return Step("available", "", "ok", facts, "Keycloak's own SPIFFE support: the route the spike takes.")
    return Step(
        "available",
        "",
        "failed",
        facts,
        "Not available: start Keycloak 26.4 or later with KC_FEATURES=spiffe, and import the realm again "
        "(spike.sh down, then up). The fallback is jwt-bearer through an OIDC identity provider (spec 046).",
    )


def step_bundle(cfg: Config) -> Step:
    status, keys = http("GET", f"{OIDC}/keys")
    _, discovery = http("GET", f"{OIDC}/.well-known/openid-configuration")
    found = keys.get("keys", [])
    return Step(
        "bundle",
        "SPIRE publishes the trust domain's JWT keys",
        "ok" if status == 200 and found else "failed",
        (
            ("trust domain", cfg.trust_domain),
            ("keys", ", ".join(f"{k.get('kid', '-')} ({k.get('kty')}/{k.get('alg', '-')})" for k in found) or "none"),
            ("discovery issuer", str(discovery.get("issuer", "-"))),
            ("Keycloak reads", "http://spire-oidc:8008/keys (its IdP's bundle endpoint)"),
        ),
    )


def step_svid(cfg: Config) -> Step:
    jwt = fetch_svid(cfg.node_id, cfg.issuer)
    path = write_svid("acl-node", jwt)
    return Step(
        "svid",
        "The agent attests the node and issues its JWT-SVID",
        "ok",
        svid_facts(jwt) + (("written to", f"{path.relative_to(HERE)} (mode 0600)"),),
        "What spiffe-helper would keep fresh on a real node.",
    )


def step_keycloak(cfg: Config, kind: str) -> Step:
    status, answer = token_request(cfg, "acl-node", fetch_svid(cfg.node_id, cfg.issuer), kind)
    title = f"Keycloak: the SVID as a client assertion of type {kind}"
    match status, answer:
        case 200, {"access_token": token}:
            return Step(f"kc-{kind}", title, "ok", access_facts(token))
        case _:
            refused = (
                ("status", str(status)),
                ("error", f"{answer.get('error')}: {answer.get('error_description', '')}"),
            )
            note = "What tresor sends today: a jwt-spiffe option is needed." if kind == "jwt-bearer" else ""
            return Step(f"kc-{kind}", title, "finding", refused, note)


def step_seed(cfg: Config) -> Step:
    status, answer = http(
        "POST",
        f"{cfg.issuer}/protocol/openid-connect/token",
        form={"grant_type": "client_credentials", "client_id": "seeder", "client_secret": "seeder-secret"},
    )
    if status != 200:
        return Step("seed", "The administrator puts a secret in the service", "failed", (("token", str(status)),))
    auth = {"Authorization": f"Bearer {answer['access_token']}"}
    put, _ = http(
        "PUT",
        f"{cfg.service}/v1/secrets/spike_lake",
        body={
            "type": "s3",
            "provider": "config",
            "scope": ["s3://spike-lake"],
            "params": {"key_id": "AKIA-SPIKE", "secret": {"type": "VARCHAR", "value": "spike-s3cret"}},
            "redact_keys": ["secret"],
        },
        headers=auth | {"If-None-Match": "*"},
    )
    grant, _ = http(
        "PUT",
        f"{cfg.service}/v1/secrets/spike_lake/grants/nodes",
        body={"principal": "role:nodes", "verbs": ["use"]},
        headers=auth,
    )
    created = {201: "created", 412: "there already"}.get(put, f"status {put}")
    return Step(
        "seed",
        "The administrator puts a secret in the service and grants role:nodes its use",
        "ok" if put in (201, 412) and grant == 200 else "failed",
        (("spike_lake (s3, s3://spike-lake)", created), ("grant role:nodes use", f"status {grant}")),
    )


def step_tresor(cfg: Config, script: str, proposed: bool) -> Step:
    path = write_svid("acl-node", fetch_svid(cfg.node_id, cfg.issuer))
    facts = tresor_facts(run_tresor(cfg, script, path))
    logged_in = any(key == "login" for key, _ in facts)
    title = (
        "tresor as spec 046 proposes: ASSERTION_SOURCE 'spiffe', SPIFFE_ID, ASSERTION_TYPE 'jwt-spiffe'"
        if proposed
        else "tresor today: FLOW 'federated', ASSERTION_FILE (sent as jwt-bearer)"
    )
    match proposed, logged_in:
        case _, True:
            return Step(script, title, "ok", facts)
        case True, False:
            return Step(script, title, "expected", facts, "Refused until the option is implemented.")
        case False, False:
            return Step(script, title, "finding", facts, "Compare with Keycloak's answer to jwt-bearer above.")


def step_intruder(cfg: Config) -> Step:
    jwt = fetch_svid(cfg.intruder_id, cfg.issuer)
    status, answer = token_request(cfg, "acl-node", jwt, "jwt-spiffe")
    facts = (
        ("SVID sub", claims(jwt)[1].get("sub", "-")),
        ("Keycloak", f"{status} {answer.get('error', 'issued a token')}"),
    )
    title = "Another attested workload presents its SVID as the node"
    if status == 200:
        return Step("intruder", title, "failed", facts, "Issued: Keycloak does not bind the client to its SPIFFE ID.")
    return Step("intruder", title, "expected", facts)


def step_audience(cfg: Config) -> Step:
    jwt = fetch_svid(cfg.node_id, "https://elsewhere.example")
    status, answer = token_request(cfg, "acl-node", jwt, "jwt-spiffe")
    facts = (
        ("SVID aud", "https://elsewhere.example"),
        ("Keycloak", f"{status} {answer.get('error', 'issued a token')}"),
    )
    title = "The node's SVID made for another audience"
    return Step("audience", title, "failed" if status == 200 else "expected", facts)


STEPS: tuple[tuple[str, str, Callable[[Config], Step]], ...] = (
    ("available", "Keycloak's own SPIFFE support is available", step_available),
    ("bundle", "SPIRE publishes the trust domain's JWT keys", step_bundle),
    ("svid", "The agent attests the node and issues its JWT-SVID", step_svid),
    ("kc-jwt-spiffe", "Keycloak: the SVID as jwt-spiffe", lambda c: step_keycloak(c, "jwt-spiffe")),
    ("kc-jwt-bearer", "Keycloak: the SVID as jwt-bearer", lambda c: step_keycloak(c, "jwt-bearer")),
    ("seed", "The administrator puts a secret in the service", step_seed),
    ("node_today.sql", "tresor today", lambda c: step_tresor(c, "node_today.sql", False)),
    ("node_proposed.sql", "tresor as proposed", lambda c: step_tresor(c, "node_proposed.sql", True)),
    ("intruder", "Another workload's SVID", step_intruder),
    ("audience", "An SVID for another audience", step_audience),
)


# --- the journal the page polls ---------------------------------------------------------------------------------


class Journal:
    """The current run's steps, shared by the run's thread and the page's requests (hence the lock)."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.steps: list[Step] = []
        self.running = False

    def put(self, step: Step) -> None:
        with self.lock:
            self.steps = [s for s in self.steps if s.id != step.id] + [step]

    def snapshot(self) -> dict:
        with self.lock:
            return {"running": self.running, "steps": [asdict(s) for s in self.steps]}

    def start(self) -> bool:
        with self.lock:
            if self.running:
                return False
            self.running, self.steps = True, []
            return True

    def stop(self) -> None:
        with self.lock:
            self.running = False


def run_all(cfg: Config, journal: Journal) -> None:
    try:
        for sid, title, run in STEPS:
            journal.put(Step(sid, title, "running"))
            try:
                result = run(cfg)
                journal.put(replace(result, id=sid, title=result.title or title))
            except SpikeError as error:
                journal.put(Step(sid, title, "failed", (("could not run", masked(str(error))),)))
            except Exception as error:  # noqa: BLE001 - a spike: show what broke and go on with the next step
                journal.put(Step(sid, title, "failed", (("error", masked(f"{type(error).__name__}: {error}")),)))
    finally:
        journal.stop()


def serve(cfg: Config) -> None:
    journal = Journal()
    page = (HERE / "console.html").read_bytes()

    class Handler(BaseHTTPRequestHandler):
        def send(self, status: int, body: bytes, kind: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", kind)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            match self.path:
                case "/":
                    self.send(200, page, "text/html; charset=utf-8")
                case "/state":
                    state = journal.snapshot() | {"config": {"issuer": cfg.issuer, "service": cfg.service,
                                                             "node": cfg.node_id}}  # fmt: skip
                    self.send(200, json.dumps(state).encode(), "application/json")
                case _:
                    self.send(404, b"{}", "application/json")

        def do_POST(self) -> None:
            match self.path:
                case "/run" if journal.start():
                    threading.Thread(target=run_all, args=(cfg, journal), daemon=True).start()
                    self.send(202, b"{}", "application/json")
                case "/run":
                    self.send(409, b'{"detail": "a run is in progress"}', "application/json")
                case _:
                    self.send(404, b"{}", "application/json")

        def log_message(self, format: str, *args: object) -> None:  # the page polls: no line per request
            pass

    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"spike console: http://127.0.0.1:{PORT}")
    server.serve_forever()


def check_available(cfg: Config) -> int:
    """spike.sh up's last word: is Keycloak's own SPIFFE support there? Printed, never a token."""
    try:
        step = step_available(cfg)
    except SpikeError as error:
        print(f"spike: Keycloak's SPIFFE support could not be checked: {error}")
        return 1
    for key, value in step.facts:
        print(f"spike:   {key}: {value}")
    print(f"spike: {step.note}")
    return 0 if step.status == "ok" else 1


if __name__ == "__main__":
    config = Config(
        issuer=os.environ["SPIKE_ISSUER"],
        service=os.environ.get("SPIKE_SERVICE", ""),
        trust_domain=os.environ["SPIKE_TRUST_DOMAIN"],
        duckdb=os.environ.get("TRESOR_DUCKDB", ""),
        extension=os.environ.get("TRESOR_EXTENSION", ""),
    )
    match sys.argv[1:]:
        case ["--available"]:
            sys.exit(check_available(config))
        case []:
            serve(config)
        case _:
            sys.exit("usage: console.py [--available]")
