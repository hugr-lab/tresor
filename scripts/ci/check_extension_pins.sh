#!/usr/bin/env bash
# Every out-of-tree extension extension_config.cmake fetches (httpfs, postgres_scanner, iceberg, avro - specs/006,
# 033) must be at the commit duckdb's own tree pins in duckdb/.github/config/extensions/<name>.cmake: their patches
# (APPLY_PATCHES) are duckdb's, written for that commit. Needs the duckdb submodule checked out.
#
#   scripts/ci/check_extension_pins.sh
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
python3 - "$root" <<'PY'
import os
import re
import sys

root = sys.argv[1]
load = re.compile(r"duckdb_extension_load\(\s*(\w+)([^)]*)\)", re.S)
tag = re.compile(r"GIT_TAG\s+([0-9a-fA-F]+)")


def pins(text):
    return {name: m.group(1) for name, body in load.findall(text) for m in [tag.search(body)] if m}


ours = pins(open(os.path.join(root, "extension_config.cmake")).read())
if not ours:
    sys.exit("check_extension_pins: no GIT_TAG in extension_config.cmake")
failed = False
for name, commit in sorted(ours.items()):
    path = os.path.join(root, "duckdb", ".github", "config", "extensions", name + ".cmake")
    if not os.path.exists(path):
        print("check_extension_pins: %s: duckdb pins no such extension (%s) - is the submodule checked out?"
              % (name, path))
        failed = True
        continue
    theirs = pins(open(path).read()).get(name)
    if theirs != commit:
        print("check_extension_pins: %s is at %s, duckdb pins %s" % (name, commit, theirs))
        failed = True
    else:
        print("check_extension_pins: %s at %s, as duckdb pins" % (name, commit[:12]))
sys.exit(1 if failed else 0)
PY
