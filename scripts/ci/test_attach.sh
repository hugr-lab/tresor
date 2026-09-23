#!/usr/bin/env bash
# The attach tests (specs/002) against the fake service + IdP (test/fake/fake_service.py): start it on a
# free loopback port, hand the port to the sqllogictests (require-env TRESOR_TEST_PORT) and play the
# person's browser with test/fake/browser.sh. Without this script the attach tests skip.
#
#   scripts/ci/test_attach.sh [unittest binary] [test pattern]
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
unittest="${1:-$root/build/release/test/unittest}"
pattern="${2:-test/sql/attach/*}"
work="$(mktemp -d)"
python3 "$root/test/fake/fake_service.py" --port-file "$work/port" &
fake=$!
trap 'kill $fake 2>/dev/null || true; rm -rf "$work"' EXIT
for _ in $(seq 50); do [ -s "$work/port" ] && break; sleep 0.1; done
[ -s "$work/port" ] || { echo "test_attach: the fake service did not start" >&2; exit 1; }
export TRESOR_TEST_PORT="$(cat "$work/port")"
export BROWSER="$root/test/fake/browser.sh"
echo "test_attach: fake service on 127.0.0.1:$TRESOR_TEST_PORT"
cd "$root"
# the runner skips a test whose error mentions "HTTP" or "Unable to connect" (a network flake guard);
# here the network is the fake, and those errors are what the tests assert - none may turn into a skip
"$unittest" --skip-error-messages '' "$pattern"
