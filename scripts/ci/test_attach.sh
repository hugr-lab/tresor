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

# LOGIN 'auto' where no browser can be opened takes the device flow: only Linux can be without one
# (macOS and Windows always have an opener), so only there, in a process without BROWSER or a display
if [ "$(uname)" = "Linux" ] && [ "$pattern" = "test/sql/attach/*" ]; then
	# its own log: the main run's summary stays the last one for scripts/ci/assert_ran.sh
	env -u BROWSER -u DISPLAY -u WAYLAND_DISPLAY TRESOR_TEST_AUTO_DEVICE=1 \
		"$unittest" --skip-error-messages '' "test/sql/attach_auto/*" >"$work/auto.log" 2>&1 || true
	if grep -q "All tests passed ([0-9]* assertions in 1 test case)" "$work/auto.log"; then
		echo "test_attach: LOGIN 'auto' without a browser took the device flow"
	else
		cat "$work/auto.log" >&2
		echo "test_attach: the LOGIN 'auto' -> device test did not pass" >&2
		exit 1
	fi
fi
