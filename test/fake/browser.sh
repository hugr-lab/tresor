#!/usr/bin/env sh
# The test "browser" (specs/002): tresor runs $BROWSER with the login URL; this follows the fake IdP's
# auto-approving 302 back to tresor's loopback receiver, which is all a person's browser would do.
exec curl -s -o /dev/null -L --max-time 20 "$1"
