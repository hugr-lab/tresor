#!/usr/bin/env python3
"""The person's browser against a real Keycloak (specs/003): tresor runs $BROWSER with the
authorization URL; this opens it, fills Keycloak's login form as TRESOR_KC_USER / TRESOR_KC_PASS and
follows the redirect back to tresor's loopback receiver - PKCE, state and Keycloak's redirect-URI
checks all real. Test credentials only.
"""
import html
import http.cookiejar
import os
import re
import sys
import urllib.parse
import urllib.request


def main():
    url = sys.argv[1]
    user = os.environ.get("TRESOR_KC_USER", "alice")
    password = os.environ.get("TRESOR_KC_PASS", "alice-pass")
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    page = opener.open(url, timeout=20).read().decode()
    # Keycloak marks its session cookies Secure even over http; a real browser treats 127.0.0.1 as a
    # secure context and sends them anyway - so does this one
    for cookie in jar:
        cookie.secure = False
    form = re.search(r'<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"', page)
    if not form:
        print("browser.py: no Keycloak login form on the authorization page", file=sys.stderr)
        return 1
    action = html.unescape(form.group(1))
    data = urllib.parse.urlencode({"username": user, "password": password, "credentialId": ""}).encode()
    # Keycloak answers 302 to the redirect_uri with code and state; the opener follows it to tresor's
    # loopback receiver, which answers the "login complete" page
    result = opener.open(action, data=data, timeout=20).read().decode()
    if "Login complete" not in result:
        print("browser.py: the login did not come back complete", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
