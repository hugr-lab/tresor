#!/usr/bin/env bash
# tresor against a real Entra ID tenant (specs/013), by hand: the reference server accepting the tenant's v2
# tokens, and a DuckDB that logs in to it as a person (the browser) - an administrator by an app role, who
# creates a secret, grants its use to roles and finds it through DuckDB's lookup, no duckdb-acl anywhere - then
# as a node with its certificate (private_key_jwt), which finds the secret granted to its role, and - when
# given - as a node with a client secret. Everything comes from the environment;
# nothing is written to the repository, and no token is ever printed. See website/docs/entra.md for the app
# registrations it expects.
#
#   ENTRA_TENANT            the tenant id
#   ENTRA_API_CLIENT_ID     the service API app's client id (a v2 token's aud)
#   ENTRA_API_URI           its Application ID URI (api://...), for the scopes
#   ENTRA_PEOPLE_CLIENT_ID  the public client people log in with
#   ENTRA_NODE_CLIENT_ID    the node app
#   ENTRA_NODE_KEY_FILE     its private key (PEM, chmod 600) and ENTRA_NODE_CERT_FILE its certificate: the
#                           certificate step and On-Behalf-Of; without them only the federated step can run
#   ENTRA_NODE_SECRET       optional: the node's client secret, for the baseline step
#   ENTRA_ADMIN_ROLE        the app role that makes a person an administrator (default secrets_admin)
#   ENTRA_USE_ROLE          an app role the person holds, granted use (default analysts)
#   ENTRA_NODE_ROLE         the node's app role, granted use too (default nodes)
#   ENTRA_SKIP_PERSON=1     skip the browser login (and the secret: the nodes then only log in)
#   ENTRA_OBO=1             also the node acting for a person's duckdb-acl session (On-Behalf-Of): the person
#                           signs in to the node's API by the device flow (the code is printed, never a token),
#                           acl opens the session, tresor exchanges the token. Needs the node's API exposed
#                           (api://<node>/sessions, v2 tokens), its delegated access_as_user consented, and the
#                           people's client allowed `sessions` (website/docs/entra.md, a node acting for its
#                           users); acl from TRESOR_ACL_EXTENSION or this build
#   ENTRA_FEDERATED=1       also the node with GitHub Actions' OIDC token as its assertion (FLOW 'federated'):
#                           only in a workflow with `id-token: write`, whose subject the node's federated
#                           credential names (.github/workflows/entra-live.yml)
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
for name in ENTRA_TENANT ENTRA_API_CLIENT_ID ENTRA_API_URI ENTRA_PEOPLE_CLIENT_ID ENTRA_NODE_CLIENT_ID; do
	[ -n "${!name:-}" ] || { echo "entra_live: $name is not set" >&2; exit 1; }
done
duckdb="$root/build/release/duckdb"
ext="$root/build/release/extension/tresor/tresor.duckdb_extension"
port="${ENTRA_SERVER_PORT:-18446}"
admin_role="${ENTRA_ADMIN_ROLE:-secrets_admin}"
use_role="${ENTRA_USE_ROLE:-analysts}"
node_role="${ENTRA_NODE_ROLE:-nodes}"
issuer="https://login.microsoftonline.com/$ENTRA_TENANT/v2.0"
work="$(mktemp -d)"
export TRESOR_KEYCHAIN=memory # a person's login stays in this process: nothing reaches the OS keychain
cleanup() {
	[ -n "${server_pid:-}" ] && kill "$server_pid" 2>/dev/null || true
	rm -rf "$work"
}
trap cleanup EXIT

cat >"$work/server.yaml" <<YAML
listen: 127.0.0.1:$port
public_url: http://127.0.0.1:$port
issuers:
  - issuer: $issuer
    audience: $ENTRA_API_CLIENT_ID
    client_id: $ENTRA_PEOPLE_CLIENT_ID
    scopes: [openid, offline_access, $ENTRA_API_URI/access_as_user]
    human_flows: [authorization_code, device_code]
    service_flows: [client_credentials, private_key_jwt]
    roles_claim: roles
    service: {claim: idtyp, equals: app, client_claim: azp}
policy:
  admins: [role:$admin_role]
  actors:
    - {principal: "client:$ENTRA_NODE_CLIENT_ID", verbs: [use]}
YAML
(cd "$root/server" && GOWORK=off go build -o "$work/ref-server" ./cmd/ref-server)
"$work/ref-server" -config "$work/server.yaml" >"$work/server.log" 2>&1 &
server_pid=$!
for _ in $(seq 50); do curl -sf "http://127.0.0.1:$port/.well-known/duckdb-secrets" >/dev/null && break; sleep 0.2; done
curl -sf "http://127.0.0.1:$port/.well-known/duckdb-secrets" >/dev/null || {
	cat "$work/server.log" >&2
	echo "entra_live: the reference server did not come up" >&2
	exit 1
}

failed=0
step() { # $1: what, $2: the SQL after LOAD, then the lines its output must hold (grep -xE patterns)
	echo "entra_live: $1"
	local out
	out="$(printf "LOAD '%s';\n%s\n" "$ext" "$2" | "$duckdb" -no-agent -unsigned -list -noheader 2>&1 || true)"
	# never a token, and never the node's secret (a parser error would quote the SQL)
	out="$(printf '%s\n' "$out" | sed -E "s/eyJ[A-Za-z0-9._-]*/<token>/g; s/ACL SESSION '[^']*'/ACL SESSION '<handle>'/g; s/\x1b\[[0-9;]*m//g")"
	if [ -n "${ENTRA_NODE_SECRET:-}" ]; then
		out="${out//"$ENTRA_NODE_SECRET"/<secret>}"
	fi
	printf '%s\n' "$out" | sed 's/^/  /'
	shift 2
	local want
	for want in "$@"; do
		if ! printf '%s\n' "$out" | grep -qxE -- "$want"; then
			echo "  FAILED: no line matching $want" >&2
			failed=1
		fi
	done
}
re() { # a role name as an ERE matches only itself (Entra's values may hold a dot)
	printf '%s' "$1" | sed 's/[][\.*^$+?(){}|]/\\&/g'
}
admin_re="$(re "$admin_role")" use_re="$(re "$use_role")" node_re="$(re "$node_role")"
whoami="SELECT 'login=' || login || ' subject=' || subject || ' roles=' || array_to_string(roles, ',') || ' can_create=' || array_to_string(can_create, ',')
    FROM e.whoami();"
host="127.0.0.1:$port"
# the secret the person writes: http, for a scope nothing resolves; its token is a placeholder, printed freely
scope="https://entra-live.invalid"
found() { # $1: the label - how many of the service's secrets DuckDB's lookup finds for the scope
	echo "SELECT '$1=' || count(*) FILTER (storage = 'e') FROM which_secret('$scope/x', 'http');"
}
listed="SELECT 'listed=' || name || ' ' || array_to_string(list_sort(permissions), ',') FROM e.secrets() WHERE name = 'entra_live';"
person=0

if [ "${ENTRA_SKIP_PERSON:-0}" != "1" ]; then
	person=1
	before="$failed"
	step "1. a person, in the browser: an administrator by role:$admin_role, using by role:$use_role" \
		"ATTACH 'tresor:$host' AS e (INSECURE_HTTP true, LOGIN 'browser'); $whoami
		 DROP PERSISTENT SECRET IF EXISTS entra_live FROM e;
		 CREATE PERSISTENT SECRET entra_live IN e (TYPE http, SCOPE '$scope', BEARER_TOKEN 'entra-live-placeholder');
		 $listed $(found before_grant)
		 SELECT 'granted=' || principal FROM e.grant_secret('entra_live', 'role:$use_role', ['use']);
		 SELECT 'granted=' || principal FROM e.grant_secret('entra_live', 'role:$node_role', ['use']);
		 $listed $(found after_grant)
		 SELECT 'revoked=' || principal FROM e.revoke_secret('entra_live', 'role:$use_role');
		 $(found after_revoke)" \
		"login=browser subject=.* roles=(.*,)?role:$admin_re(,.*)? can_create=\\*" \
		"login=browser subject=.* roles=(.*,)?role:$use_re(,.*)? can_create=\\*" \
		"listed=entra_live annotate,delete,grant,update" \
		"before_grant=0" \
		"granted=role:$use_re" \
		"granted=role:$node_re" \
		"listed=entra_live annotate,delete,grant,update,use" \
		"after_grant=1" \
		"revoked=role:$use_re" \
		"after_revoke=0"
	# a failed step 1 leaves no secret for the node: its lookup is then not checked, not failed
	[ "$failed" = "$before" ] || { person=0; echo "  (the nodes' lookup is not checked: step 1 failed)"; }
fi
# the node finds what an administrator granted its role - when the person made it in this run
node_checks=("login=private_key_jwt subject=.* roles=(.*,)?role:$node_re(,.*)? can_create=")
[ "$person" = 1 ] && node_checks+=("node=1")
has_key=0
[ -n "${ENTRA_NODE_KEY_FILE:-}" ] && [ -n "${ENTRA_NODE_CERT_FILE:-}" ] && has_key=1
if [ "$has_key" = 1 ]; then
step "2. the node with its certificate (private_key_jwt)" \
	"CREATE SECRET n (TYPE tresor, SCOPE 'tresor:$host', FLOW 'client_credentials', CLIENT_ID '$ENTRA_NODE_CLIENT_ID',
	    ISSUER '$issuer', OAUTH_SCOPE '$ENTRA_API_URI/.default', PRIVATE_KEY_FILE '$ENTRA_NODE_KEY_FILE',
	    CERTIFICATE_FILE '$ENTRA_NODE_CERT_FILE');
	 ATTACH 'tresor:$host' AS e (INSECURE_HTTP true, SECRET n); $whoami $(found node)" \
	"${node_checks[@]}"
fi
if [ -n "${ENTRA_NODE_SECRET:-}" ]; then
	node_checks[0]="login=client_credentials subject=.* roles=(.*,)?role:$node_re(,.*)? can_create="
	step "3. the node with its client secret (the baseline)" \
		"CREATE SECRET n (TYPE tresor, SCOPE 'tresor:$host', FLOW 'client_credentials', CLIENT_ID '$ENTRA_NODE_CLIENT_ID',
		    ISSUER '$issuer', OAUTH_SCOPE '$ENTRA_API_URI/.default', CLIENT_SECRET '$ENTRA_NODE_SECRET');
		 ATTACH 'tresor:$host' AS e (INSECURE_HTTP true, SECRET n); $whoami $(found node)" \
		"${node_checks[@]}"
fi
if [ "${ENTRA_OBO:-0}" = "1" ]; then
	[ "$has_key" = 1 ] || { echo "entra_live: ENTRA_OBO needs the node's key and certificate" >&2; exit 1; }
	acl_ext="${TRESOR_ACL_EXTENSION:-$root/build/release/extension/acl/acl.duckdb_extension}"
	[ -f "$acl_ext" ] || { echo "entra_live: no duckdb-acl at $acl_ext (TRESOR_ACL_EXTENSION)" >&2; exit 1; }
	echo "entra_live: 4. the person signs in to the node's API (device flow):"
	# the token stays in this process's memory and reaches the DuckDB process only through its environment
	session_token="$(python3 - "$ENTRA_TENANT" "$ENTRA_PEOPLE_CLIENT_ID" "api://$ENTRA_NODE_CLIENT_ID/sessions" <<'PY'
import json, sys, time, urllib.parse, urllib.request, urllib.error
tenant, client, scope = sys.argv[1:4]
base = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0"
def post(url, form):
    req = urllib.request.Request(url, urllib.parse.urlencode(form).encode())
    try:
        return json.load(urllib.request.urlopen(req))
    except urllib.error.HTTPError as e:
        return json.load(e)
code = post(base + "/devicecode", {"client_id": client, "scope": scope})
if "device_code" not in code:
    sys.exit("device flow refused: " + code.get("error", "?") + " " + code.get("error_description", "")[:200])
print("  " + code["message"], file=sys.stderr)
deadline = time.time() + int(code.get("expires_in", 900))
while time.time() < deadline:
    time.sleep(int(code.get("interval", 5)))
    answer = post(base + "/token", {"grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                                     "client_id": client, "device_code": code["device_code"]})
    if "access_token" in answer:
        token = answer["access_token"]
        # what acl will check, to diagnose a refusal: claims only, never the token
        import base64
        part = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
        shown = {k: claims.get(k) for k in ("iss", "aud", "ver", "scp", "azp", "appid")}
        print("  the session token claims: " + json.dumps(shown), file=sys.stderr)
        print(token)
        sys.exit(0)
    if answer.get("error") == "slow_down":
        code["interval"] = int(code.get("interval", 5)) + 5  # RFC 8628 3.5
    elif answer.get("error") != "authorization_pending":
        sys.exit("device flow: " + answer.get("error", "?") + " " + answer.get("error_description", "")[:200])
sys.exit("device flow: expired")
PY
)"
	under="$work/under_session.sql"
	# a line `session=… actor=…` exists only under a delegation grant: the node's own whoami has no actor
	obo_checks=("acting=true on_behalf_of" "session=[^ ]+ actor=client:$ENTRA_NODE_CLIENT_ID" "closed=true")
	[ "$person" = 1 ] && obo_checks+=("session_lake=entra_live")
	export ENTRA_SESSION_TOKEN="$session_token"
	step "4. the node acting for the person's duckdb-acl session (On-Behalf-Of)" \
		"CREATE SECRET n (TYPE tresor, SCOPE 'tresor:$host', FLOW 'client_credentials', CLIENT_ID '$ENTRA_NODE_CLIENT_ID',
		    ISSUER '$issuer', OAUTH_SCOPE '$ENTRA_API_URI/.default', PRIVATE_KEY_FILE '$ENTRA_NODE_KEY_FILE',
		    CERTIFICATE_FILE '$ENTRA_NODE_CERT_FILE');
		 ATTACH 'tresor:$host' AS e (INSECURE_HTTP true, SECRET n);
		 LOAD '$acl_ext';
		 -- acl reads the issuer's discovery through httpfs, which refuses a document whose HEAD size and GET
		 -- differ - Entra answers HEAD with another (HTML) page: small files are read whole, until duckdb-acl
		 -- reads its documents whole itself (its spec 101)
		 SET GLOBAL force_download_threshold = 1048576;
		 ATTACH ':memory:' AS store;
		 SELECT acl_use_db('store', 'acl', true) IS NOT NULL;
		 SET GLOBAL acl_allow_anonymous_admin = true;
		 -- the person's token for the node: aud the node's client id, its delegated scope the acl role
		 ACL ADMIN CREATE ISSUER '$issuer' AUDIENCES ('$ENTRA_NODE_CLIENT_ID') ROLE CLAIM 'scp';
		 SELECT 'acting=' || changed || ' ' || exchange FROM e.act_for_sessions(exchange := 'on_behalf_of',
		     exchange_scope := '$ENTRA_API_URI/.default');
		 ACL ADMIN CREATE ROLE sessions;
		 ACL ADMIN CREATE VIRTUAL CATALOG c;
		 ACL ADMIN CREATE VIRTUAL TABLE FUNCTION c.me RETURNS TABLE (subject VARCHAR, actor VARCHAR)
		     AS SELECT subject, actor FROM e.main.whoami();
		 ACL ADMIN CREATE VIRTUAL TABLE FUNCTION c.lake RETURNS TABLE (name VARCHAR)
		     AS SELECT name FROM which_secret('$scope/x', 'http') WHERE storage = 'e';
		 ACL ADMIN GRANT CATALOG c TO ROLE sessions WITH (select) MAIN;
		 -- the handle is a bearer credential: it reaches $under (in the run's own 0700 directory, removed at exit,
		 -- useless once this process ends) as test/acl/actor.sql does, and the output masks it
		 CREATE TABLE h AS SELECT acl_session_open(getenv('ENTRA_SESSION_TOKEN')) AS handle;
		 SELECT 'opened=' || (handle IS NOT NULL) FROM h;
		 -- a refusal's reason is acl's audit's (its ring), never the door's
		 SELECT acl_audit_flush() IS NOT NULL;
		 SELECT 'refused=' || coalesce(reason_code, '') || ': ' || coalesce(reason, '') FROM acl_audit_events()
		     WHERE kind = 'session' AND detail = 'refused';
.output $under
		 SELECT acl_session_sql(handle, 'SELECT ''session='' || subject || '' actor='' || actor FROM c.me()') || ';' FROM h;
		 SELECT acl_session_sql(handle, 'SELECT ''session_lake='' || name FROM c.lake()') || ';' FROM h;
.output
.read $under
		 SELECT 'closed=' || acl_session_close(handle) FROM h;" \
		"${obo_checks[@]}" "opened=true"
	unset ENTRA_SESSION_TOKEN session_token
	# the grant ends with the session: tresor revokes it asynchronously - give it a moment, then the server says
	for _ in $(seq 20); do
		grep -qE 'method=DELETE path=/v1/delegations/… status=(200|204|404)' "$work/server.log" && break
		sleep 0.5
	done
	if grep -qE 'method=DELETE path=/v1/delegations/… status=(200|204|404)' "$work/server.log"; then
		echo "  revoked: the grant ended with the session"
	else
		echo "  FAILED: the grant was not revoked when the session closed" >&2
		failed=1
	fi
fi
if [ "${ENTRA_FEDERATED:-0}" = "1" ]; then
	[ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ] || {
		echo "entra_live: ENTRA_FEDERATED needs GitHub Actions' token service (id-token: write)" >&2
		exit 1
	}
	federated_checks=("login=federated subject=.* roles=(.*,)?role:$node_re(,.*)? can_create=")
	[ "$person" = 1 ] && federated_checks+=("federated_node=1")
	step "5. the node federated: GitHub Actions' OIDC token as its assertion" \
		"CREATE SECRET n (TYPE tresor, SCOPE 'tresor:$host', FLOW 'federated', CLIENT_ID '$ENTRA_NODE_CLIENT_ID',
		    ISSUER '$issuer', OAUTH_SCOPE '$ENTRA_API_URI/.default', ASSERTION_SOURCE 'github_actions',
		    ASSERTION_AUDIENCE 'api://AzureADTokenExchange');
		 ATTACH 'tresor:$host' AS e (INSECURE_HTTP true, SECRET n); $whoami $(found federated_node)" \
		"${federated_checks[@]}"
fi
echo "entra_live: the reference server's view (subjects, no tokens):"
grep -E 'msg=request' "$work/server.log" | sed -E 's/^/  /' | tail -10
exit "$failed"
