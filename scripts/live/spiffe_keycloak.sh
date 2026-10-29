#!/usr/bin/env bash
# Check 5 (specs/046), locally: a SPIFFE workload's JWT-SVID as a Keycloak client's federated assertion. SPIRE (server,
# agent, OIDC discovery provider) and Keycloak with the realm examples/spiffe-spike/keycloak/realm-spiffe.json (an
# identity provider of type spiffe, the spiffe preview feature on) run in docker compose - the spike's compose file
# and configs, under a project and ports of their own, so the spike may run beside it; the reference server runs
# here. The agent issues the node's SVID for the realm, and scripts/live/run.sh spiffe_keycloak logs in with it.
# What must be refused:
#   - the node's SVID sent as jwt-bearer: Keycloak's SPIFFE authentication takes jwt-spiffe only (invalid_client);
#   - another attested workload's SVID with the node's SPIFFE_ID: tresor never sends it;
#   - the node's SVID made for another audience: tresor never sends it.
# Needs docker (compose), go and python3; nothing is printed of any token.
#
#   KEYCLOAK_VERSION (default 26.8.1; 26.4 or later)  SPIRE_VERSION (default 1.13.0)  KEEP_STAND=1 leaves it running
#   TRESOR_DUCKDB / TRESOR_EXTENSION: a build (default build/release)
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
spike="$root/examples/spiffe-spike"
export KEYCLOAK_VERSION="${KEYCLOAK_VERSION:-26.8.1}" SPIRE_VERSION="${SPIRE_VERSION:-1.13.0}"
export KEYCLOAK_PORT="${KEYCLOAK_PORT:-18492}" SPIRE_OIDC_PORT="${SPIRE_OIDC_PORT:-18457}"
server_port="${TRESOR_SERVER_PORT:-18458}"
issuer="http://127.0.0.1:$KEYCLOAK_PORT/realms/spiffe"
td="spiffe://tresor.example"
agent_id="$td/agent/live"
node_id="$td/node/acl-node"
compose=(docker compose -p tresor-spiffe-live -f "$spike/docker-compose.yml")
work="$(mktemp -d)"
cleanup() {
	[ -n "${server_pid:-}" ] && kill "$server_pid" 2>/dev/null || true
	if [ "${KEEP_STAND:-0}" != "1" ]; then "${compose[@]}" down -v >/dev/null 2>&1 || true; fi
	rm -rf "$work"
}
trap cleanup EXIT
server_cli() { "${compose[@]}" exec -T spire-server /opt/spire/bin/spire-server "$@" -socketPath /run/spire/sockets/server/api.sock; }
wait_for() { # $1 what, $2.. the command
	local what="$1"
	shift
	for _ in $(seq 120); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done
	echo "spiffe_keycloak: $what did not come up" >&2
	exit 1
}

echo "spiffe_keycloak: SPIRE $SPIRE_VERSION, Keycloak $KEYCLOAK_VERSION"
"${compose[@]}" up -d --quiet-pull spire-server keycloak
wait_for "the SPIRE server" server_cli healthcheck
if ! "${compose[@]}" ps --status running spire-agent | grep -q spire-agent; then
	token="$(server_cli token generate -spiffeID "$agent_id" | awk '/^Token:/ {print $2}')"
	SPIRE_JOIN_TOKEN="$token" "${compose[@]}" up -d --quiet-pull spire-agent spire-oidc
	unset token
fi
for id in "$node_id" "$td/node/intruder"; do
	out="$(server_cli entry create -parentID "$agent_id" -spiffeID "$id" -selector unix:uid:0 2>&1)" ||
		grep -qi 'already exists\|similar entry' <<<"$out" || { echo "$out" >&2; exit 1; }
done
wait_for "SPIRE's OIDC discovery" curl -sf "http://127.0.0.1:$SPIRE_OIDC_PORT/keys"
wait_for "Keycloak's realm" curl -sf "$issuer/.well-known/openid-configuration"
# the route is Keycloak's own SPIFFE support: refuse to judge tresor against a Keycloak without it
SPIKE_ISSUER="$issuer" SPIKE_TRUST_DOMAIN="$td" python3 "$spike/console.py" --available | sed 's/^spike:/spiffe_keycloak:/'

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
curl -sf "http://127.0.0.1:$server_port/.well-known/duckdb-secrets" >/dev/null || {
	sed -E 's/eyJ[A-Za-z0-9._-]*/<token>/g' "$work/server.log" | tail -20 >&2
	echo "spiffe_keycloak: the reference server did not come up" >&2
	exit 1
}

# what spiffe-helper writes: the workload's JWT-SVID for an audience, in a file only its owner reads
svid() { # $1 the SPIFFE ID, $2 the audience, $3 the file
	local fetched
	# read whole, then parsed: an awk that stops at the token would cut the agent's pipe (pipefail, set -e)
	fetched="$("${compose[@]}" exec -T spire-agent /opt/spire/bin/spire-agent api fetch jwt -audience "$2" \
		-spiffeID "$1" -socketPath /run/spire/sockets/agent/api.sock)" || { echo "spiffe_keycloak: no SVID for $1" >&2; exit 1; }
	(umask 077 && awk 'found {gsub(/[ \t]/, ""); print; exit} /^token\(/ {found = 1}' <<<"$fetched" >"$3")
	unset fetched
	[ -s "$3" ] || { echo "spiffe_keycloak: no SVID for $1" >&2; exit 1; }
}
export TRESOR_URL="http://127.0.0.1:$server_port" TRESOR_ISSUER="$issuer" TRESOR_CLIENT_ID=acl-node
export TRESOR_SPIFFE_ID="$node_id"
export TRESOR_DUCKDB="${TRESOR_DUCKDB:-$root/build/release/duckdb}"
export TRESOR_EXTENSION="${TRESOR_EXTENSION:-$root/build/release/extension/tresor/tresor.duckdb_extension}"
failed=0
refused() { # $1 what, $2 the line that must be in the log, then the environment for run.sh
	local what="$1" want="$2"
	shift 2
	echo "spiffe_keycloak: $what must be refused"
	if env "$@" "$root/scripts/live/run.sh" spiffe_keycloak >"$work/refused.log" 2>&1; then
		cat "$work/refused.log"
		echo "spiffe_keycloak: FAILED - $what logged in" >&2
		failed=1
	elif grep -qF -- "$want" "$work/refused.log"; then
		grep -E 'federated login' "$work/refused.log" | sed 's/^ */  /'
	else
		cat "$work/refused.log"
		echo "spiffe_keycloak: FAILED - not refused with: $want" >&2
		failed=1
	fi
}

svid "$node_id" "$issuer" "$work/node.jwt"
TRESOR_ASSERTION_FILE="$work/node.jwt" "$root/scripts/live/run.sh" spiffe_keycloak || failed=1
refused "the node's SVID as jwt-bearer" "failed: invalid_client" \
	TRESOR_ASSERTION_FILE="$work/node.jwt" TRESOR_ASSERTION_TYPE=jwt-bearer
svid "$td/node/intruder" "$issuer" "$work/intruder.jwt"
refused "another workload's SVID" "is $td/node/intruder, not SPIFFE_ID $node_id - never sent" \
	TRESOR_ASSERTION_FILE="$work/intruder.jwt"
svid "$node_id" "https://elsewhere.example" "$work/elsewhere.jwt"
refused "an SVID for another audience" "is not meant for $issuer (its aud: https://elsewhere.example) - never sent" \
	TRESOR_ASSERTION_FILE="$work/elsewhere.jwt"

if [ "$failed" = 1 ]; then
	echo "spiffe_keycloak: Keycloak's log (federated client auth):" >&2
	"${compose[@]}" logs --tail 40 keycloak | sed -E 's/eyJ[A-Za-z0-9._-]*/<token>/g' >&2
else
	echo "spiffe_keycloak: PASSED"
fi
exit "$failed"
