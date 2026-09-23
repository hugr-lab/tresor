#!/usr/bin/env bash
# The reference server next to a real Keycloak (specs/003): start Keycloak with the test realm
# (server/docker-compose.yml), build and start tresor-server, then run the conformance suite
# (test/sql/conformance/*) and the reference server's own tests (test/sql/reference_server/*) against
# the pair - a service login with client credentials, and a person's browser login played by
# test/keycloak/browser.py. Needs docker and go.
#
#   scripts/ci/test_keycloak.sh [unittest binary]      # KEEP_KEYCLOAK=1 leaves Keycloak running
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
unittest="${1:-$root/build/release/test/unittest}"
work="$(mktemp -d)"
kc_port="${KEYCLOAK_PORT:-18480}"
issuer="http://127.0.0.1:$kc_port/realms/tresor"
compose=(docker compose -p tresor-kc -f "$root/server/docker-compose.yml")

cleanup() {
	[ -n "${server_pid:-}" ] && kill "$server_pid" 2>/dev/null || true
	[ "${KEEP_KEYCLOAK:-0}" = "1" ] || "${compose[@]}" down >/dev/null 2>&1 || true
	rm -rf "$work"
}
trap cleanup EXIT

echo "test_keycloak: starting Keycloak on 127.0.0.1:$kc_port"
KEYCLOAK_PORT="$kc_port" "${compose[@]}" up -d
for _ in $(seq 120); do curl -sf "$issuer/.well-known/openid-configuration" >/dev/null && break; sleep 2; done
curl -sf "$issuer/.well-known/openid-configuration" >/dev/null || {
	"${compose[@]}" logs --tail 50 >&2
	echo "test_keycloak: Keycloak did not come up" >&2
	exit 1
}

echo "test_keycloak: building and starting tresor-server"
(cd "$root/server" && GOWORK=off go build -o "$work/tresor-server" ./cmd/tresor-server)
"$work/tresor-server" -config "$root/server/testdata/keycloak/server.yaml" >"$work/server.log" 2>&1 &
server_pid=$!
for _ in $(seq 50); do curl -sf http://127.0.0.1:18443/.well-known/duckdb-secrets >/dev/null && break; sleep 0.2; done

export TRESOR_CONFORMANCE_HOST=127.0.0.1:18443 TRESOR_CONFORMANCE_INSECURE=true
export TRESOR_CONFORMANCE_ISSUER="$issuer" TRESOR_CONFORMANCE_CLIENT_ID=etl TRESOR_CONFORMANCE_CLIENT_SECRET=etl-secret
export TRESOR_CONFORMANCE_PERSON=1 TRESOR_KC_HOST=127.0.0.1:18443 TRESOR_KC_ISSUER="$issuer"
export BROWSER="$root/test/keycloak/browser.py" TRESOR_KC_USER=alice TRESOR_KC_PASS=alice-pass
cd "$root"
status=0
# the reference server's own tests first, so the conformance run's summary is the last one printed
# (scripts/ci/assert_ran.sh reads the last); both must pass
"$unittest" --skip-error-messages '' 'test/sql/reference_server/*' >"$work/reference.log" 2>&1 || status=1
if ! grep -q "All tests passed" "$work/reference.log" || grep -q "skipped" "$work/reference.log"; then
	cat "$work/reference.log" >&2
	status=1
else
	echo "test_keycloak: the reference server's tests passed ($(grep -o '[0-9]* assertions in [0-9]* test case[s]*' "$work/reference.log"))"
fi
"$unittest" --skip-error-messages '' 'test/sql/conformance/*' || status=1
if [ "$status" != 0 ]; then
	echo "--- tresor-server log ---" >&2
	cat "$work/server.log" >&2
fi
exit "$status"
