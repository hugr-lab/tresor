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
#   ENTRA_NODE_KEY_FILE     its private key (PEM, chmod 600) and ENTRA_NODE_CERT_FILE its certificate
#   ENTRA_NODE_SECRET       optional: the node's client secret, for the baseline step
#   ENTRA_ADMIN_ROLE        the app role that makes a person an administrator (default secrets_admin)
#   ENTRA_USE_ROLE          an app role the person holds, granted use (default analysts)
#   ENTRA_NODE_ROLE         the node's app role, granted use too (default nodes)
#   ENTRA_SKIP_PERSON=1     skip the browser login (and the secret: the nodes then only log in)
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
for name in ENTRA_TENANT ENTRA_API_CLIENT_ID ENTRA_API_URI ENTRA_PEOPLE_CLIENT_ID ENTRA_NODE_CLIENT_ID \
	ENTRA_NODE_KEY_FILE ENTRA_NODE_CERT_FILE; do
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
YAML
(cd "$root/server" && GOWORK=off go build -o "$work/tresor-server" ./cmd/tresor-server)
"$work/tresor-server" -config "$work/server.yaml" >"$work/server.log" 2>&1 &
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
	out="$(printf "LOAD '%s';\n%s\n" "$ext" "$2" | "$duckdb" -unsigned -list -noheader 2>&1 || true)"
	# never a token, and never the node's secret (a parser error would quote the SQL)
	out="$(printf '%s\n' "$out" | sed -E 's/eyJ[A-Za-z0-9._-]*/<token>/g')"
	if [ -n "${ENTRA_NODE_SECRET:-}" ]; then
		out="${out//$ENTRA_NODE_SECRET/<secret>}"
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
		"login=browser subject=.* roles=(.*,)?role:$admin_role(,.*)? can_create=\\*" \
		"login=browser subject=.* roles=(.*,)?role:$use_role(,.*)? can_create=\\*" \
		"listed=entra_live annotate,delete,grant,update" \
		"before_grant=0" \
		"granted=role:$use_role" \
		"granted=role:$node_role" \
		"listed=entra_live annotate,delete,grant,update,use" \
		"after_grant=1" \
		"revoked=role:$use_role" \
		"after_revoke=0"
fi
# the node finds what an administrator granted its role - when the person made it in this run
node_checks=("login=private_key_jwt subject=.* roles=(.*,)?role:$node_role(,.*)? can_create=")
[ "$person" = 1 ] && node_checks+=("node=1")
step "2. the node with its certificate (private_key_jwt)" \
	"CREATE SECRET n (TYPE tresor, SCOPE 'tresor:$host', FLOW 'client_credentials', CLIENT_ID '$ENTRA_NODE_CLIENT_ID',
	    ISSUER '$issuer', OAUTH_SCOPE '$ENTRA_API_URI/.default', PRIVATE_KEY_FILE '$ENTRA_NODE_KEY_FILE',
	    CERTIFICATE_FILE '$ENTRA_NODE_CERT_FILE');
	 ATTACH 'tresor:$host' AS e (INSECURE_HTTP true, SECRET n); $whoami $(found node)" \
	"${node_checks[@]}"
if [ -n "${ENTRA_NODE_SECRET:-}" ]; then
	node_checks[0]="login=client_credentials subject=.* roles=(.*,)?role:$node_role(,.*)? can_create="
	step "3. the node with its client secret (the baseline)" \
		"CREATE SECRET n (TYPE tresor, SCOPE 'tresor:$host', FLOW 'client_credentials', CLIENT_ID '$ENTRA_NODE_CLIENT_ID',
		    ISSUER '$issuer', OAUTH_SCOPE '$ENTRA_API_URI/.default', CLIENT_SECRET '$ENTRA_NODE_SECRET');
		 ATTACH 'tresor:$host' AS e (INSECURE_HTTP true, SECRET n); $whoami $(found node)" \
		"${node_checks[@]}"
fi
echo "entra_live: the reference server's view (subjects, no tokens):"
grep -E 'msg=request' "$work/server.log" | sed -E 's/^/  /' | tail -10
exit "$failed"
