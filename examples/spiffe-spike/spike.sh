#!/usr/bin/env bash
# The SPIFFE spike (tresor specs/046), by hand:
#
#   spike.sh up        SPIRE (server, agent, OIDC discovery), Keycloak trusting it, the reference server
#   spike.sh console   the console at http://127.0.0.1:18455 - runs each step and shows what happened
#   spike.sh down      stops everything and forgets the trust domain
#
# Needs docker (compose), go, python3, and a tresor build (TRESOR_DUCKDB, TRESOR_EXTENSION; default the
# repository's build/release). Nothing it prints holds a token. KEYCLOAK_VERSION (default 26.8.1), SPIRE_VERSION
# (default 1.13.0).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
run="$here/run"
kc_port="${KEYCLOAK_PORT:-18491}"
server_port="${TRESOR_SERVER_PORT:-18454}"
issuer="http://127.0.0.1:$kc_port/realms/spiffe"
td="spiffe://tresor.example"
agent_id="$td/agent/spike"
compose=(docker compose -p tresor-spiffe -f "$here/docker-compose.yml")
server_cli() { "${compose[@]}" exec -T spire-server /opt/spire/bin/spire-server "$@" -socketPath /run/spire/sockets/server/api.sock; }

wait_for() { # $1 what, $2.. the command
	local what="$1"
	shift
	for _ in $(seq 90); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done
	echo "spike: $what did not come up" >&2
	return 1
}

register() { # $1 the SPIFFE ID - every workload of uid 0 in the agent's container may ask for it
	local out
	if ! out="$(server_cli entry create -parentID "$agent_id" -spiffeID "$1" -selector unix:uid:0 2>&1)"; then
		grep -qi 'already exists\|similar entry' <<<"$out" || { echo "$out" >&2; return 1; }
	fi
	echo "spike: registered $1"
}

up() {
	mkdir -p "$run/svid"
	chmod 700 "$run/svid"
	"${compose[@]}" up -d spire-server keycloak
	wait_for "the SPIRE server" server_cli healthcheck
	if ! "${compose[@]}" ps --status running spire-agent | grep -q spire-agent; then
		local token
		token="$(server_cli token generate -spiffeID "$agent_id" | awk '/^Token:/ {print $2}')"
		[ -n "$token" ] || { echo "spike: no join token" >&2; exit 1; }
		SPIRE_JOIN_TOKEN="$token" "${compose[@]}" up -d spire-agent spire-oidc
	fi
	register "$td/node/acl-node"
	register "$td/node/intruder" # an attested workload, but not the one Keycloak's client names
	wait_for "SPIRE's OIDC discovery" curl -sf "http://127.0.0.1:${SPIRE_OIDC_PORT:-18456}/keys"
	wait_for "Keycloak's realm" curl -sf "$issuer/.well-known/openid-configuration"

	cat >"$run/server.yaml" <<YAML
listen: 127.0.0.1:$server_port
public_url: http://127.0.0.1:$server_port
issuers:
  - issuer: $issuer
    audience: duckdb-secrets
    service_flows: [federated, client_credentials]
    roles_claim: realm_access.roles
    service: {claim: client_id}
policy:
  admins: [role:secrets_admin]
YAML
	if [ -f "$run/ref-server.pid" ] && kill -0 "$(cat "$run/ref-server.pid")" 2>/dev/null; then
		echo "spike: the reference server runs already"
	else
		(cd "$root/server" && GOWORK=off go build -o "$run/ref-server" ./cmd/ref-server)
		"$run/ref-server" -config "$run/server.yaml" >"$run/ref-server.log" 2>&1 &
		echo $! >"$run/ref-server.pid"
	fi
	wait_for "the reference server" curl -sf "http://127.0.0.1:$server_port/.well-known/duckdb-secrets"
	# Keycloak's own SPIFFE support is the route (specs/046): say plainly when this Keycloak does not have it
	if SPIKE_ISSUER="$issuer" SPIKE_TRUST_DOMAIN="$td" python3 "$here/console.py" --available; then
		echo "spike: Keycloak's SPIFFE support is available"
	else
		echo "spike: WARNING - Keycloak's SPIFFE support is not available; the jwt-spiffe steps will fail" >&2
	fi
	echo "spike: up - SPIRE ($td), Keycloak $issuer, the service http://127.0.0.1:$server_port"
	echo "spike: next, $0 console"
}

down() {
	if [ -f "$run/ref-server.pid" ]; then
		kill "$(cat "$run/ref-server.pid")" 2>/dev/null || true
	fi
	"${compose[@]}" down -v
	rm -rf "$run"
}

case "${1:-}" in
up) up ;;
down) down ;;
console)
	export SPIKE_ISSUER="$issuer" SPIKE_SERVICE="http://127.0.0.1:$server_port" SPIKE_TRUST_DOMAIN="$td"
	export TRESOR_DUCKDB="${TRESOR_DUCKDB:-$root/build/release/duckdb}"
	export TRESOR_EXTENSION="${TRESOR_EXTENSION:-$root/build/release/extension/tresor/tresor.duckdb_extension}"
	exec python3 "$here/console.py"
	;;
*)
	echo "usage: spike.sh up|console|down" >&2
	exit 2
	;;
esac
