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
# creating is not using (specs/009): the etl service's role is granted use, as an admin grants it
curl -sf -o /dev/null -X PUT "http://127.0.0.1:$server_port/v1/secrets/conformance_lake/grants/etl" \
	-H "Authorization: Bearer $etl_token" -H 'Content-Type: application/json' \
	-d '{"principal":"role:etl","verbs":["use"]}' || {
	echo "test_keycloak: granting the conformance secret failed" >&2
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
# a user's token as a duckdb-acl node receives it (specs/008): alice through the acl-door client, whose
# tokens are meant for acl-node only - the actor test exchanges it at Keycloak for one meant for the service.
# Fetched last, right before the tests: it lives Keycloak's default five minutes
TRESOR_KC_DOOR_TOKEN="$(curl -sf -d grant_type=password -d client_id=acl-door -d username=alice \
	-d password=alice-pass -d scope=openid "$issuer/protocol/openid-connect/token" |
	python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])' || true)"
[ -n "$TRESOR_KC_DOOR_TOKEN" ] || {
	echo "test_keycloak: no token for alice through acl-door - cannot run the actor test" >&2
	exit 1
}
# ... and bob's, an admin: administration through the node (specs/009)
TRESOR_KC_DOOR_TOKEN_ADMIN="$(curl -sf -d grant_type=password -d client_id=acl-door -d username=bob \
	-d password=bob-pass -d scope=openid "$issuer/protocol/openid-connect/token" |
	python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])' || true)"
[ -n "$TRESOR_KC_DOOR_TOKEN_ADMIN" ] || {
	echo "test_keycloak: no token for bob through acl-door - cannot run the actor test" >&2
	exit 1
}
export TRESOR_KC_DOOR_TOKEN TRESOR_KC_DOOR_TOKEN_ADMIN

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
# with duckdb-acl itself (specs/008): TRESOR_ACL_EXTENSION names an acl.duckdb_extension built at this
# repository's duckdb commit - a real acl session's statements run as its user, through the grant
# (or the test build carries one: TRESOR_TEST_ACL_DIR, extension_config.cmake)
built_acl="$(dirname "$unittest")/../extension/acl/acl.duckdb_extension"
if [ -z "${TRESOR_ACL_EXTENSION:-}" ] && [ -f "$built_acl" ]; then
	TRESOR_ACL_EXTENSION="$built_acl"
fi
if [ -n "${TRESOR_ACL_EXTENSION:-}" ]; then
	cli="${TRESOR_CLI:-$(dirname "$unittest")/../duckdb}"
	door_token="$(curl -sf -d grant_type=password -d client_id=acl-door -d username=alice -d password=alice-pass \
		-d scope=openid "$issuer/protocol/openid-connect/token" |
		python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')"
	admin_token="$(curl -sf -d grant_type=password -d client_id=acl-door -d username=bob -d password=bob-pass \
		-d scope=openid "$issuer/protocol/openid-connect/token" |
		python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')"
	jwks="$(curl -sf "$issuer/protocol/openid-connect/certs")"
	sed -e "s|@ACL_EXTENSION@|$TRESOR_ACL_EXTENSION|" \
		-e "s|@TRESOR_EXTENSION@|$(dirname "$unittest")/../extension/tresor/tresor.duckdb_extension|" \
		-e "s|@HOST@|127.0.0.1:$server_port|g" -e "s|@ISSUER@|$issuer|g" -e "s|@WORK@|$work|g" \
		-e "s|@TOKEN@|$door_token|" -e "s|@ADMIN_TOKEN@|$admin_token|" -e "s|@JWKS@|$jwks|" \
		"$root/test/acl/actor.sql" >"$work/acl.sql"
	logged="$(wc -l <"$work/server.log")" # the reference tests made and revoked grants too: only the new lines count
	# the stub linked into the test CLI must not mark acl's hooks: the real duckdb-acl is what must (ACLC 2)
	ACL_STUB_NO_MARK=1 "$cli" -unsigned <"$work/acl.sql" >"$work/acl.log" 2>&1 || true
	[ -n "${TRESOR_ACL_DEBUG:-}" ] && sed -E -e 's/eyJ[A-Za-z0-9._-]*/<token>/g' -e 's/[0-9A-Fa-f]{32}/<handle>/g' \
		"$work/acl.log" >"$TRESOR_ACL_DEBUG"
	tail -n +"$((logged + 1))" "$work/server.log" >"$work/acl_server.log"
	[ -n "${TRESOR_ACL_DEBUG:-}" ] && cp "$work/acl_server.log" "$TRESOR_ACL_DEBUG.server"
	checks=(
		'^check:refused-before-acl 0$'
		'^check:node [0-9a-f-]{36}\|NULL$'
		'^check:node-lake 1$'
		'^check:opened true$'
		'^check:session [0-9a-f-]{36}\|client:acl-node$'
		'^check:session-lake acl_lake$'
		'^check:closed true$'
		'^check:admin-made 1$'
		'^check:admin-granted role:analysts$'
		'^check:nonadmin-granted role:analysts$'
		'^check:nonadmin-made 0$'
		'^check:admin-closed true$'
		'^check:admin-dropped 0$'
	)
	acl_ok=1
	for check in "${checks[@]}"; do
		grep -Eq "$check" "$work/acl.log" || { echo "test_keycloak: acl: no line matching $check" >&2; acl_ok=0; }
	done
	grep -q 'method=POST path=/v1/delegations status=201' "$work/acl_server.log" || {
		echo "test_keycloak: acl: no grant was made" >&2
		acl_ok=0
	}
	grep -q 'method=DELETE path=/v1/delegations/.* status=204' "$work/acl_server.log" || {
		echo "test_keycloak: acl: no grant was revoked" >&2
		acl_ok=0
	}
	if [ "$acl_ok" = 1 ]; then
		echo "test_keycloak: with duckdb-acl, a session's statements ran as its user, and its grant was revoked;" \
			"an admin managed secrets through the node, a user who is none could not"
	else
		# the checks and the errors only, and never a token (even a cut-off one) or a session handle: an error
		# may quote a statement with alice's token or the handle in it
		grep -E '^check:|Error' "$work/acl.log" |
			sed -E -e 's/eyJ[A-Za-z0-9._-]*/<token>/g' -e 's/[0-9A-Fa-f]{32}/<handle>/g' >&2 || true
		status=1
	fi
fi
"$unittest" --skip-error-messages '' 'test/sql/conformance/*' || status=1
if [ "$status" != 0 ]; then
	echo "--- tresor-server log ---" >&2
	cat "$work/server.log" >&2
fi
exit "$status"
