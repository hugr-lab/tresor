#!/usr/bin/env bash
# tresor against a real Entra ID tenant (specs/013), by hand: the reference server accepting the tenant's v2
# tokens, and a DuckDB that logs in to it as a person (the browser), as a node with its certificate
# (private_key_jwt), and - when given - as a node with a client secret. Everything comes from the environment;
# nothing is written to the repository, and no token is ever printed. See website/docs/reference-server.md
# ("Entra ID, checked live") for the app registrations it expects.
#
#   ENTRA_TENANT            the tenant id
#   ENTRA_API_CLIENT_ID     the service API app's client id (a v2 token's aud)
#   ENTRA_API_URI           its Application ID URI (api://...), for the scopes
#   ENTRA_PEOPLE_CLIENT_ID  the public client people log in with
#   ENTRA_NODE_CLIENT_ID    the node app
#   ENTRA_NODE_KEY_FILE     its private key (PEM, chmod 600) and ENTRA_NODE_CERT_FILE its certificate
#   ENTRA_NODE_SECRET       optional: the node's client secret, for the baseline step
#   ENTRA_SKIP_PERSON=1     skip the browser login
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
for name in ENTRA_TENANT ENTRA_API_CLIENT_ID ENTRA_API_URI ENTRA_PEOPLE_CLIENT_ID ENTRA_NODE_CLIENT_ID \
	ENTRA_NODE_KEY_FILE ENTRA_NODE_CERT_FILE; do
	[ -n "${!name:-}" ] || { echo "entra_live: $name is not set" >&2; exit 1; }
done
duckdb="$root/build/release/duckdb"
ext="$root/build/release/extension/tresor/tresor.duckdb_extension"
port="${ENTRA_SERVER_PORT:-18446}"
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
  admins: []
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

step() { # $1: what, then the SQL after LOAD
	echo "entra_live: $1"
	printf "LOAD '%s';\n%s\n" "$ext" "$2" | "$duckdb" -unsigned -list -noheader 2>&1 |
		sed -E -e 's/eyJ[A-Za-z0-9._-]*/<token>/g' -e 's/^/  /' || true
}
whoami="SELECT 'login=' || login || ' subject=' || subject || ' roles=' || roles::VARCHAR FROM e.whoami();"
host="127.0.0.1:$port"

if [ "${ENTRA_SKIP_PERSON:-0}" != "1" ]; then
	step "1. a person, in the browser" \
		"ATTACH 'tresor:$host' AS e (INSECURE_HTTP true, LOGIN 'browser'); $whoami"
fi
step "2. the node with its certificate (private_key_jwt)" \
	"CREATE SECRET n (TYPE tresor, SCOPE 'tresor:$host', FLOW 'client_credentials', CLIENT_ID '$ENTRA_NODE_CLIENT_ID',
	    ISSUER '$issuer', OAUTH_SCOPE '$ENTRA_API_URI/.default', PRIVATE_KEY_FILE '$ENTRA_NODE_KEY_FILE',
	    CERTIFICATE_FILE '$ENTRA_NODE_CERT_FILE');
	 ATTACH 'tresor:$host' AS e (INSECURE_HTTP true, SECRET n); $whoami"
if [ -n "${ENTRA_NODE_SECRET:-}" ]; then
	step "3. the node with its client secret (the baseline)" \
		"CREATE SECRET n (TYPE tresor, SCOPE 'tresor:$host', FLOW 'client_credentials', CLIENT_ID '$ENTRA_NODE_CLIENT_ID',
		    ISSUER '$issuer', OAUTH_SCOPE '$ENTRA_API_URI/.default', CLIENT_SECRET '$ENTRA_NODE_SECRET');
		 ATTACH 'tresor:$host' AS e (INSECURE_HTTP true, SECRET n); $whoami"
fi
echo "entra_live: the reference server's view (subjects, no tokens):"
grep -E 'msg=request' "$work/server.log" | sed -E 's/^/  /' | tail -10
