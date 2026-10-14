#!/bin/sh
# tresor live check (specs/027): one service login against the stand's service, judged by whoami.
#   check.sh mi | fed | aks | kc
# Env: TRESOR_URL TRESOR_ISSUER TRESOR_AUDIENCE TRESOR_API_URI TRESOR_ACL_CLIENT_ID
#      TRESOR_MI_CLIENT_ID (mi, fed) TRESOR_ASSERTION_FILE (aks, kc)
# kc: Keycloak's federated client authentication - TRESOR_ISSUER the realm, TRESOR_ACL_CLIENT_ID its client
#     (Signed JWT - Federated), TRESOR_ASSERTION_FILE the projected token with the realm as its audience
# Exit 0 only when whoami says the expected login and role:nodes. Prints no token.
set -u
host="${TRESOR_URL#https://}"; host="${host%/}"
ext="${TRESOR_EXTENSION:-/opt/tresor/tresor.duckdb_extension}"
duckdb="${TRESOR_DUCKDB:-/usr/local/bin/duckdb}"
case "${1:-}" in
mi)
	want=managed_identity
	secret="FLOW 'managed_identity', ISSUER '$TRESOR_ISSUER', AUDIENCE '$TRESOR_AUDIENCE', CLIENT_ID '$TRESOR_MI_CLIENT_ID'" ;;
fed)
	want=federated
	secret="FLOW 'federated', CLIENT_ID '$TRESOR_ACL_CLIENT_ID', ISSUER '$TRESOR_ISSUER', OAUTH_SCOPE '$TRESOR_API_URI/.default', ASSERTION_SOURCE 'azure_managed_identity', IDENTITY_CLIENT_ID '$TRESOR_MI_CLIENT_ID'" ;;
aks)
	want=federated
	secret="FLOW 'federated', CLIENT_ID '$TRESOR_ACL_CLIENT_ID', ISSUER '$TRESOR_ISSUER', OAUTH_SCOPE '$TRESOR_API_URI/.default', ASSERTION_FILE '$TRESOR_ASSERTION_FILE'" ;;
kc)
	want=federated
	secret="FLOW 'federated', CLIENT_ID '$TRESOR_ACL_CLIENT_ID', ISSUER '$TRESOR_ISSUER', ASSERTION_FILE '$TRESOR_ASSERTION_FILE'" ;;
*) echo "usage: check.sh mi|fed|aks|kc" >&2; exit 2 ;;
esac
out="$(TRESOR_KEYCHAIN=off "$duckdb" -unsigned -no-agent -list -noheader -c "
LOAD '$ext';
CREATE SECRET n (TYPE tresor, SCOPE 'tresor:$host', $secret);
ATTACH 'tresor:$host' AS e (SECRET n);
SELECT 'login=' || login || ' roles=' || array_to_string(roles, ',') FROM e.whoami();
SELECT 'listed=' || count(*) FROM e.secrets();" 2>&1)"
status=$?
# never a token in the log, whatever an error quotes
printf '%s\n' "$out" | sed -E 's/eyJ[A-Za-z0-9._-]*/<token>/g'
[ "$status" -eq 0 ] || { echo "tresor check $1: duckdb exited $status" >&2; exit 1; }
printf '%s\n' "$out" | grep -qE "^login=$want roles=(.*,)?role:nodes(,.*)?$" || { echo "tresor check $1: FAILED - expected login=$want with role:nodes" >&2; exit 1; }
echo "tresor check $1: ok"
