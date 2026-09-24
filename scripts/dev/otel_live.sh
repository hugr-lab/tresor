#!/usr/bin/env bash
# A live look at tresor's audit as OpenTelemetry (specs/011): tresor, duckdb-acl and acl-otel in one DuckDB,
# exporting to acl-otel's local stack (deploy/local-stack: Collector, Tempo, Loki, Grafana). Not a CI test -
# a bench, run by hand, to see that tresor's spans hang under the statement's trace and its log records
# arrive. Keycloak and the reference server as scripts/ci/test_keycloak.sh starts them.
#
#   scripts/dev/otel_live.sh            # needs: docker, go, the local stack up, a test build with acl
#
# ACL_OTEL_EXTENSION names acl_otel.duckdb_extension built at this repository's duckdb commit (default: the
# sibling checkout's build). Prints the trace id; Grafana: http://localhost:3000 -> Explore -> Tempo.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
duckdb="$root/build/release/duckdb"
tresor_ext="$root/build/release/extension/tresor/tresor.duckdb_extension"
acl_ext="${TRESOR_ACL_EXTENSION:-$root/build/release/extension/acl/acl.duckdb_extension}"
otel_ext="${ACL_OTEL_EXTENSION:-$root/../acl-otel/build/release/extension/acl_otel/acl_otel.duckdb_extension}"
otlp="${OTLP_ENDPOINT:-http://127.0.0.1:4318}"
tempo="${TEMPO_URL:-http://127.0.0.1:3200}"
loki="${LOKI_URL:-http://127.0.0.1:3100}"
kc_port="${KEYCLOAK_PORT:-18481}"
server_port="${TRESOR_SERVER_PORT:-18444}"
issuer="http://127.0.0.1:$kc_port/realms/tresor"
service="tresor-live-$$"
work="$(mktemp -d)"
compose=(docker compose -p tresor-kc-live -f "$root/server/docker-compose.yml")

for f in "$duckdb" "$tresor_ext" "$acl_ext" "$otel_ext"; do
	[ -f "$f" ] || { echo "otel_live: missing $f" >&2; exit 1; }
done
curl -sf -o /dev/null "$tempo/ready" || { echo "otel_live: Tempo not at $tempo - start the local stack" >&2; exit 1; }
for port in "$kc_port" "$server_port"; do
	if curl -s -o /dev/null "http://127.0.0.1:$port/"; then
		echo "otel_live: 127.0.0.1:$port is taken - set KEYCLOAK_PORT / TRESOR_SERVER_PORT" >&2
		exit 1
	fi
done

cleanup() {
	[ -n "${server_pid:-}" ] && kill "$server_pid" 2>/dev/null || true
	[ -n "${echo_pid:-}" ] && kill "$echo_pid" 2>/dev/null || true
	[ "${KEEP_KEYCLOAK:-0}" = "1" ] || "${compose[@]}" down >/dev/null 2>&1 || true
	rm -rf "$work"
}
trap cleanup EXIT

KEYCLOAK_PORT="$kc_port" "${compose[@]}" up -d
for _ in $(seq 120); do curl -sf "$issuer/.well-known/openid-configuration" >/dev/null && break; sleep 2; done
curl -sf "$issuer/.well-known/openid-configuration" >/dev/null || {
	"${compose[@]}" logs --tail 50 >&2
	echo "otel_live: Keycloak did not come up" >&2
	exit 1
}
(cd "$root/server" && GOWORK=off go build -o "$work/tresor-server" ./cmd/tresor-server)
sed -e "s/127.0.0.1:18480/127.0.0.1:$kc_port/g" -e "s/127.0.0.1:18443/127.0.0.1:$server_port/g" \
	"$root/server/testdata/keycloak/server.yaml" >"$work/server.yaml"
TRESOR_EXCHANGE_SECRET=svc-secret "$work/tresor-server" -config "$work/server.yaml" >"$work/server.log" 2>&1 &
server_pid=$!
python3 "$root/test/keycloak/echo.py" --port-file "$work/echo.port" &
echo_pid=$!
for _ in $(seq 50); do [ -s "$work/echo.port" ] && break; sleep 0.1; done
echo_host="127.0.0.1:$(cat "$work/echo.port")"
for _ in $(seq 50); do curl -sf "http://127.0.0.1:$server_port/.well-known/duckdb-secrets" >/dev/null && break; sleep 0.2; done
if ! kill -0 "$server_pid" 2>/dev/null || ! curl -sf "http://127.0.0.1:$server_port/.well-known/duckdb-secrets" >/dev/null; then
	cat "$work/server.log" >&2
	echo "otel_live: tresor-server did not come up" >&2
	exit 1
fi

token() { # client, then user/password or nothing (client credentials)
	if [ $# -eq 3 ]; then
		curl -sf -d grant_type=password -d client_id="$1" -d username="$2" -d password="$3" -d scope=openid \
			"$issuer/protocol/openid-connect/token"
	else
		curl -sf -d grant_type=client_credentials -d client_id="$1" -d client_secret="$2" \
			"$issuer/protocol/openid-connect/token"
	fi | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])'
}
etl="$(token etl etl-secret)"
api="http://127.0.0.1:$server_port/v1/secrets"
# a token-for-the-caller secret for the echo API (specs/010), usable by the node's role
curl -sf -o /dev/null -X PUT "$api/live_echo" -H "Authorization: Bearer $etl" -H 'Content-Type: application/json' \
	-d '{"type":"http","provider":"token_exchange","scope":["http://'"$echo_host"'"],"params":{"audience":"echo-api"},"redact_keys":[]}'
curl -sf -o /dev/null -X PUT "$api/live_echo/grants/nodes" -H "Authorization: Bearer $etl" \
	-H 'Content-Type: application/json' -d '{"principal":"role:nodes","verbs":["use"]}'
alice="$(token acl-door alice alice-pass)"
jwks="$(curl -sf "$issuer/protocol/openid-connect/certs")"
q="'"
jwks="${jwks//$q/$q$q}" # a SQL string literal below

trace_id="$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
span_id="$(python3 -c 'import secrets; print(secrets.token_hex(8))')"
traceparent="00-$trace_id-$span_id-01"

cat >"$work/live.sql" <<SQL
.mode list
.headers off
LOAD '$tresor_ext';
LOAD '$acl_ext';
LOAD '$otel_ext';
SET GLOBAL acl_otel_endpoint = '$otlp';
SET GLOBAL acl_otel_service_name = '$service';
SET GLOBAL acl_otel_traces = 'linked';
SET GLOBAL acl_audit_level = 'all';
SET tresor_audit_level = 'all';
CALL enable_logging('tresor', storage = 'memory');
ATTACH ':memory:' AS store;
SELECT acl_use_db('store', 'acl', true) AS ok;
SET GLOBAL acl_allow_anonymous_admin = true;
SELECT acl_define_issuer('$issuer', '$jwks', 'acl-node', 'RS256', 'realm_access.roles', '{}') AS ok;
CREATE SECRET node (TYPE tresor, SCOPE 'tresor:elsewhere', FLOW 'client_credentials', CLIENT_ID 'acl-node',
    CLIENT_SECRET 'node-secret', ISSUER '$issuer');
ATTACH 'tresor:127.0.0.1:$server_port' AS node (INSECURE_HTTP true, SECRET node, ACT_FOR_SESSIONS true);
ACL ADMIN CREATE ROLE analysts;
ACL ADMIN CREATE VIRTUAL CATALOG c;
ACL ADMIN CREATE VIRTUAL TABLE FUNCTION c.who RETURNS TABLE (who VARCHAR)
    AS SELECT trim(content) FROM read_text('http://$echo_host/who');
ACL ADMIN GRANT CATALOG c TO ROLE analysts WITH (select) MAIN;
CREATE TABLE h AS SELECT acl_session_open('$alice') AS handle;
SELECT 'opened ' || (handle IS NOT NULL) FROM h;
SET acl_correlation_id = 'live-1';
SET acl_traceparent = '$traceparent';
.output $work/under.sql
SELECT acl_session_sql(handle, 'SELECT ''who '' || who FROM c.who()') || ';' FROM h;
.output
.read $work/under.sql
RESET acl_traceparent;
RESET acl_correlation_id;
SELECT 'closed ' || acl_session_close(handle) FROM h;
DETACH node;
SELECT 'tresor-log ' || kind || ' ' || outcome || ' principal=' || coalesce(principal, '-') || ' user=' ||
       coalesce("user", '-') || ' trace=' || coalesce(traceparent, '-')
FROM duckdb_logs_parsed('tresor') ORDER BY seq;
SELECT acl_audit_flush();
SELECT acl_otel_flush();
SELECT acl_otel_traces_flush();
SELECT acl_otel_metrics_flush();
SELECT 'otel-status ' || acl_otel_status();
SQL

echo "otel_live: trace $trace_id, service $service"
# the acl_stub linked into the test CLI must not mark acl's hooks: the real duckdb-acl does (ACLC 2)
# a failed statement does not end the bench: what reached the service, Tempo and Loki is the diagnosis
(ACL_STUB_NO_MARK=1 "$duckdb" -unsigned <"$work/live.sql" 2>&1 || true) | sed -E 's/eyJ[A-Za-z0-9._-]*/<token>/g' |
	sed 's/^/  duckdb: /'
echo "otel_live: the reference server's line for the traced request:"
grep -F "$trace_id" "$work/server.log" | sed 's/^/  server: /' || echo "  server: (none)"

sleep 8 # the Collector batches; Tempo ingests
echo "otel_live: Tempo's trace $trace_id"
curl -sf "$tempo/api/traces/$trace_id" -H 'Accept: application/json' | python3 -c '
import json, sys, base64
doc = json.load(sys.stdin)
spans = []
for batch in doc.get("batches", doc.get("resourceSpans", [])):
    for scope in batch.get("scopeSpans", batch.get("instrumentationLibrarySpans", [])):
        name = scope.get("scope", scope.get("instrumentationLibrary", {})).get("name", "")
        for s in scope.get("spans", []):
            dec = lambda v: base64.b64decode(v).hex() if v else ""
            ms = (int(s["endTimeUnixNano"]) - int(s["startTimeUnixNano"])) / 1e6
            spans.append((dec(s.get("parentSpanId")), dec(s["spanId"]), s["name"], name, ms))
ids = {s[1]: s[2] for s in spans}
for parent, sid, nm, scope, ms in sorted(spans, key=lambda s: s[2]):
    print("  span: %-24s scope=%-8s %8.2f ms  parent=%s" % (nm, scope, ms, ids.get(parent, parent or "-")))
print("  spans: %d" % len(spans))
' || echo "  (Tempo has no such trace yet)"
echo "otel_live: Loki's tresor records for $service"
curl -sfG "$loki/loki/api/v1/query_range" --data-urlencode "query={service_name=\"$service\"} |= \"tresor\"" \
	--data-urlencode "limit=20" | python3 -c '
import json, sys
for stream in json.load(sys.stdin)["data"]["result"]:
    for ts, line in stream["values"]:
        print("  log: " + line[:160])
' || echo "  (Loki answered nothing)"
