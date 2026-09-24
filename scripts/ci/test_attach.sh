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
# services without a shared secret (specs/013): keys made for this run only - the fake verifies assertions with
# the public halves; a group-readable copy must be refused; a federated token file as a platform would mount it
keys="$work/keys"
mkdir -p "$keys"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$keys/keynode.pem" 2>/dev/null
openssl pkey -in "$keys/keynode.pem" -pubout -out "$keys/keynode.pub"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$keys/eckeynode.pem" 2>/dev/null
openssl pkey -in "$keys/eckeynode.pem" -pubout -out "$keys/eckeynode.pub"
openssl req -x509 -new -key "$keys/keynode.pem" -subj /CN=keynode -days 1 -out "$keys/keynode.crt" 2>/dev/null
chmod 600 "$keys/keynode.pem" "$keys/eckeynode.pem"
cp "$keys/keynode.pem" "$keys/keynode-open.pem"
chmod 644 "$keys/keynode-open.pem"
printf 'platform-jwt\n' >"$keys/fed.token"
export TRESOR_TEST_KEYS="$keys"
python3 "$root/test/fake/fake_service.py" --port-file "$work/port" &
fake=$!
trap 'kill $fake 2>/dev/null || true; rm -rf "$work"' EXIT
for _ in $(seq 50); do [ -s "$work/port" ] && break; sleep 0.1; done
[ -s "$work/port" ] || { echo "test_attach: the fake service did not start" >&2; exit 1; }
export TRESOR_TEST_PORT="$(cat "$work/port")"
export BROWSER="$root/test/fake/browser.sh"
# the Azure App Service identity endpoint and GitHub Actions' token service, both the fake's (specs/013)
export IDENTITY_ENDPOINT="http://127.0.0.1:$TRESOR_TEST_PORT/msi/token" IDENTITY_HEADER=test-mi
export ACTIONS_ID_TOKEN_REQUEST_URL="http://127.0.0.1:$TRESOR_TEST_PORT/gh?api-version=2.0"
export ACTIONS_ID_TOKEN_REQUEST_TOKEN=test-gh
# a person's login is remembered in this instance's memory only (specs/012): a test never touches the OS keychain
export TRESOR_KEYCHAIN=memory
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
