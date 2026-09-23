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
server_port="${TRESOR_SERVER_PORT:-18443}"
issuer="http://127.0.0.1:$kc_port/realms/tresor"
# a project of its own: `docker compose -p tresor-kc` is the developer's standing Keycloak, left alone
compose=(docker compose -p tresor-kc-test -f "$root/server/docker-compose.yml")

for port in "$kc_port" "$server_port"; do
	if curl -s -o /dev/null "http://127.0.0.1:$port/"; then
		echo "test_keycloak: 127.0.0.1:$port is taken - set KEYCLOAK_PORT / TRESOR_SERVER_PORT" >&2
		exit 1
	fi
done

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
# the test config, on the ports of this run
sed -e "s/127.0.0.1:18480/127.0.0.1:$kc_port/g" -e "s/127.0.0.1:18443/127.0.0.1:$server_port/g" \
	"$root/server/testdata/keycloak/server.yaml" >"$work/server.yaml"
"$work/tresor-server" -config "$work/server.yaml" >"$work/server.log" 2>&1 &
server_pid=$!
for _ in $(seq 50); do curl -sf "http://127.0.0.1:$server_port/.well-known/duckdb-secrets" >/dev/null && break; sleep 0.2; done
if ! kill -0 "$server_pid" 2>/dev/null || ! curl -sf "http://127.0.0.1:$server_port/.well-known/duckdb-secrets" >/dev/null; then
	cat "$work/server.log" >&2
	echo "test_keycloak: tresor-server did not come up" >&2
	exit 1
fi

# a secret for the conformance suite to find, put through the protocol by the etl service itself
etl_token="$(curl -sf -d grant_type=client_credentials -d client_id=etl -d client_secret=etl-secret \
	"$issuer/protocol/openid-connect/token" | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])' ||
	true)"
[ -n "$etl_token" ] || {
	echo "test_keycloak: no token for the etl service - cannot seed the conformance secret" >&2
	exit 1
}
curl -sf -o /dev/null -X PUT "http://127.0.0.1:$server_port/v1/secrets/conformance_lake" \
	-H "Authorization: Bearer $etl_token" -H 'Content-Type: application/json' -H 'If-None-Match: *' \
	-d '{"type":"s3","provider":"config","scope":["s3://conformance-lake"],
	     "params":{"key_id":"AKIA-CONFORMANCE","secret":{"type":"VARCHAR","value":"s3cr3t"}},"redact_keys":["secret"]}' || {
	echo "test_keycloak: seeding the conformance secret failed" >&2
	exit 1
}
export TRESOR_CONFORMANCE_SECRET=conformance_lake TRESOR_CONFORMANCE_SECRET_TYPE=s3
export TRESOR_CONFORMANCE_SECRET_PATH=s3://conformance-lake/x.parquet
export TRESOR_CONFORMANCE_SECRET_KEY=key_id TRESOR_CONFORMANCE_SECRET_VALUE=AKIA-CONFORMANCE

export TRESOR_CONFORMANCE_HOST=127.0.0.1:$server_port TRESOR_CONFORMANCE_INSECURE=true
export TRESOR_CONFORMANCE_ISSUER="$issuer" TRESOR_CONFORMANCE_CLIENT_ID=etl TRESOR_CONFORMANCE_CLIENT_SECRET=etl-secret
export TRESOR_CONFORMANCE_PERSON=1 TRESOR_KC_HOST=127.0.0.1:$server_port TRESOR_KC_ISSUER="$issuer"
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
	# not in the runner's summary format: assert_ran must only ever read the conformance run's line
	echo "test_keycloak: the reference server's tests passed"
fi
"$unittest" --skip-error-messages '' 'test/sql/conformance/*' || status=1
if [ "$status" != 0 ]; then
	echo "--- tresor-server log ---" >&2
	cat "$work/server.log" >&2
fi
exit "$status"
