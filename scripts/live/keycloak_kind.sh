#!/usr/bin/env bash
# Check 4 (specs/027), locally: a Kubernetes service-account token as a Keycloak client's federated assertion.
# A kind cluster runs Keycloak (scripts/live/keycloak-kind.yaml, the realm server/testdata/keycloak/
# realm-federated.json) trusting the cluster's tokens; the reference server runs here with that realm as its
# issuer; the cluster mints a token for tresor-logins/duckdb with the realm as its audience (the TokenRequest API,
# what a projected volume gets); scripts/live/run.sh k8s_keycloak logs in with it. A token of another service
# account must be refused, and so must the right token under another client id. Needs docker, kind, kubectl and go; nothing is printed of any token.
#
#   KIND=<kind binary>  KEYCLOAK_VERSION (default 26.8.1)  KEEP_KIND=1 leaves the cluster
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
kind="${KIND:-kind}"
cluster=tresor-fed
ctx="kind-$cluster"
kc_version="${KEYCLOAK_VERSION:-26.8.1}"
kc_port="${KEYCLOAK_PORT:-18490}"
server_port="${TRESOR_SERVER_PORT:-18453}"
issuer="http://127.0.0.1:$kc_port/realms/federated"
work="$(mktemp -d)"
created=0
cleanup() {
	[ -n "${forward_pid:-}" ] && kill "$forward_pid" 2>/dev/null || true
	[ -n "${server_pid:-}" ] && kill "$server_pid" 2>/dev/null || true
	if [ "$created" = 1 ] && [ "${KEEP_KIND:-0}" != "1" ]; then "$kind" delete cluster --name "$cluster" >/dev/null 2>&1 || true; fi
	rm -rf "$work"
}
trap cleanup EXIT

if ! "$kind" get clusters 2>/dev/null | grep -qx "$cluster"; then
	"$kind" create cluster --name "$cluster" --wait 120s
	created=1
fi
k=(kubectl --context "$ctx")
"${k[@]}" create namespace keycloak --dry-run=client -o yaml | "${k[@]}" apply -f - >/dev/null
"${k[@]}" -n keycloak create configmap keycloak-realm \
	--from-file=realm-federated.json="$root/server/testdata/keycloak/realm-federated.json" --dry-run=client -o yaml |
	"${k[@]}" apply -f - >/dev/null
sed "s/KEYCLOAK_VERSION/$kc_version/" "$root/scripts/live/keycloak-kind.yaml" | "${k[@]}" apply -f - >/dev/null
echo "keycloak_kind: Keycloak $kc_version starting in $ctx"
"${k[@]}" -n keycloak rollout status deploy/keycloak --timeout=600s
"${k[@]}" -n keycloak port-forward deploy/keycloak "$kc_port:8080" >"$work/forward.log" 2>&1 &
forward_pid=$!
for _ in $(seq 60); do curl -sf "$issuer/.well-known/openid-configuration" >/dev/null && break; sleep 1; done
curl -sf "$issuer/.well-known/openid-configuration" >/dev/null || { echo "keycloak_kind: the realm is not reachable" >&2; exit 1; }

cat >"$work/server.yaml" <<YAML
listen: 127.0.0.1:$server_port
public_url: http://127.0.0.1:$server_port
issuers:
  - issuer: $issuer
    audience: duckdb-secrets
    service_flows: [federated]
    roles_claim: realm_access.roles
    service: {claim: client_id}
policy:
  admins: [role:secrets_admin]
YAML
(cd "$root/server" && GOWORK=off go build -o "$work/ref-server" ./cmd/ref-server)
"$work/ref-server" -config "$work/server.yaml" >"$work/server.log" 2>&1 &
server_pid=$!
for _ in $(seq 50); do curl -sf "http://127.0.0.1:$server_port/.well-known/duckdb-secrets" >/dev/null && break; sleep 0.2; done

# what a projected volume holds: a TokenRequest token for the service account, its audience the realm
mint() { # $1 the service account, $2 the file
	"${k[@]}" -n tresor-logins create token "$1" --audience "$issuer" --duration 10m >"$2"
	chmod 440 "$2"
}
"${k[@]}" -n tresor-logins get serviceaccount default >/dev/null
mint duckdb "$work/token"
export TRESOR_URL="http://127.0.0.1:$server_port" TRESOR_ISSUER="$issuer" TRESOR_CLIENT_ID=k8s-node
export TRESOR_DUCKDB="${TRESOR_DUCKDB:-$root/build/release/duckdb}"
export TRESOR_EXTENSION="${TRESOR_EXTENSION:-$root/build/release/extension/tresor/tresor.duckdb_extension}"
failed=0
TRESOR_ASSERTION_FILE="$work/token" "$root/scripts/live/run.sh" k8s_keycloak || failed=1

echo "keycloak_kind: another service account's token must be refused"
mint default "$work/other"
if TRESOR_ASSERTION_FILE="$work/other" "$root/scripts/live/run.sh" k8s_keycloak >"$work/other.log" 2>&1; then
	cat "$work/other.log"
	echo "keycloak_kind: FAILED - tresor-logins/default logged in as k8s-node" >&2
	failed=1
else
	grep -E 'federated login|FAILED' "$work/other.log" | sed 's/^/  /'
fi
echo "keycloak_kind: the right token under another CLIENT_ID must be refused (Keycloak matches client_id)"
if TRESOR_ASSERTION_FILE="$work/token" TRESOR_CLIENT_ID=not-k8s-node "$root/scripts/live/run.sh" k8s_keycloak \
	>"$work/wrong.log" 2>&1; then
	cat "$work/wrong.log"
	echo "keycloak_kind: FAILED - CLIENT_ID not-k8s-node logged in" >&2
	failed=1
else
	grep -E 'federated login|FAILED' "$work/wrong.log" | sed 's/^/  /'
fi
if [ "$failed" = 1 ]; then
	echo "keycloak_kind: Keycloak's log (federated client auth):" >&2
	"${k[@]}" -n keycloak logs deploy/keycloak --tail 40 | sed -E 's/eyJ[A-Za-z0-9._-]*/<token>/g' >&2
fi
exit "$failed"
