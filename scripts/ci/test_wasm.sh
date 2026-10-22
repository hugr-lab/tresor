#!/usr/bin/env bash
# specs/042: tresor's wasm build in a browser. DuckDB-wasm's own shell (shell.duckdb.org, DuckDB v2.0.0 wasm_eh,
# from duckdb-wasm's gh-pages at SHELL_COMMIT) and tresor's tresor.duckdb_extension.wasm are served by the fake
# service under /web/ - one origin, so the page needs no CORS - and test/wasm/shell.mjs drives it in Chromium:
# the imports resolved against that engine, then LOAD, the page's login handed over, ATTACH, whoami, the secrets.
#
#   scripts/ci/test_wasm.sh [extension .wasm]     (default: build/wasm_eh/extension/tresor/tresor.duckdb_extension.wasm)
#
# Needs node; `npm ci` in test/wasm and `npx playwright install chromium` once (CI does both).
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
extension="${1:-$root/build/wasm_eh/extension/tresor/tresor.duckdb_extension.wasm}"
# duckdb-wasm's gh-pages: "Web shell: interactive before the engine loads" - the shell on DuckDB v2.0.0 (d54cbbe)
SHELL_COMMIT=7464a0ff883f1a67bc8011bb051174aba22b01d7
SHELL_ASSETS="static/assets/duckdb.946a785b55.js static/assets/duckdb.32c6463d0f.wasm static/assets/worker.8db4dcde36.js
static/assets/duckdb-eh.f88168bf7a.wasm"
[ -f "$extension" ] || { echo "test_wasm: no extension at $extension (make wasm_eh)" >&2; exit 1; }
work="$(mktemp -d)"
cleanup() {
	[ -n "${fake_pid:-}" ] && kill "$fake_pid" 2>/dev/null || true
	rm -rf "$work"
}
trap cleanup EXIT

web="$work/web"
mkdir -p "$web/static/assets"
for path in index.html $SHELL_ASSETS; do
	curl -sfL --retry 3 -o "$web/$path" "https://raw.githubusercontent.com/duckdb/duckdb-wasm/$SHELL_COMMIT/$path"
done
cp "$extension" "$web/tresor.duckdb_extension.wasm"
# what LOAD will resolve: every symbol tresor imports is exported by this engine (or tresor itself)
python3 "$root/scripts/ci/wasm_imports.py" "$extension" "$web/static/assets/duckdb-eh.f88168bf7a.wasm"

python3 "$root/test/fake/fake_service.py" --port-file "$work/port" --web-dir "$web" &
fake_pid=$!
for _ in $(seq 50); do [ -s "$work/port" ] && break; sleep 0.1; done
port="$(cat "$work/port")"

node "$root/test/wasm/shell.mjs" "http://127.0.0.1:$port"
