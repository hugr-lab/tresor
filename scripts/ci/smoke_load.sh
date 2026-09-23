#!/usr/bin/env bash
# The artifact must LOAD, not only compile: symbol visibility, a runtime dependency that resolved on
# the build machine only, an init that throws - all pass a build and fail the first user. The built
# file is used from outside the tree by the CLI, as an operator would. Two scenarios (specs/001):
#   1. an explicit LOAD of the copied artifact answers tresor_version();
#   2. installed into a fresh extension directory, the artifact is loaded by `ATTACH 'tresor:...'`
#      ALONE - no LOAD, autoloading off - which is the design's single entry point.
#
#   scripts/ci/smoke_load.sh [<extension file>] [<duckdb binary>] [<local extension repository>]
set -euo pipefail
ext="${1:-build/release/extension/tresor/tresor.duckdb_extension}"
duckdb="${2:-build/release/duckdb}"
repo="${3:-build/release/repository}"
[ -f "$ext" ] || { echo "smoke_load: no extension at $ext" >&2; exit 1; }
[ -x "$duckdb" ] || { echo "smoke_load: no duckdb CLI at $duckdb" >&2; exit 1; }
[ -d "$repo" ] || { echo "smoke_load: no local extension repository at $repo" >&2; exit 1; }
ext_abs="$(cd "$(dirname "$ext")" && pwd)/$(basename "$ext")"
duckdb_abs="$(cd "$(dirname "$duckdb")" && pwd)/$(basename "$duckdb")"
repo_abs="$(cd "$repo" && pwd)"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
cp "$ext_abs" "$tmp/tresor.duckdb_extension"
cd "$tmp"

# 1. explicit LOAD of the copied artifact
out="$("$duckdb_abs" -unsigned -csv -noheader -c "
LOAD '$tmp/tresor.duckdb_extension';
SELECT 'version=' || coalesce(tresor_version(), '<null>');
" 2>&1)" || { echo "smoke_load: the artifact did not load:" >&2; echo "$out" >&2; exit 1; }
grep -q '^version=' <<<"$out" || { echo "smoke_load: no version answer:" >&2; echo "$out" >&2; exit 1; }

# 2. the ATTACH alone loads the installed extension (the discovery of a name that cannot resolve
#    fails with tresor's own message - the proof that tresor's code ran)
att="$("$duckdb_abs" -unsigned -csv -noheader -c "
SET extension_directories = ['$tmp/extensions'];
SET autoload_known_extensions = false;
INSTALL tresor FROM '$repo_abs';
ATTACH 'tresor:secrets.example.invalid' AS corp;
" 2>&1)" && { echo "smoke_load: an ATTACH of an unresolvable service succeeded - expected tresor's discovery error" >&2; exit 1; }
grep -q "tresor: discovery of secrets.example.invalid failed" <<<"$att" || {
	echo "smoke_load: ATTACH 'tresor:...' did not reach tresor's attach (was the extension loaded by prefix?):" >&2
	echo "$att" >&2
	exit 1
}
echo "smoke_load: ok ($out; ATTACH 'tresor:...' loads the installed extension; size $(wc -c <"$ext_abs" | tr -d ' ') bytes)"
