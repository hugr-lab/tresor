#!/usr/bin/env python3
"""The person approving a device login at a real Keycloak (duckdb-ext-common spec 017, tresor's device flow):
follows the link with the code (verification_uri_complete; a bare verification_uri gets the code typed), fills
Keycloak's login form as TRESOR_KC_USER / TRESOR_KC_PASS and grants the consent if one is asked. Test
credentials only.

    device.py <verification_uri_complete> <user_code>
"""
import html
import http.cookiejar
import os
import re
import sys
import urllib.parse
import urllib.request


def form_of(page, form_id=None):
    """The action and the hidden inputs of the page's form (by id when given, else the first)."""
    pattern = r'<form[^>]*id="%s"[^>]*>(.*?)</form>' % form_id if form_id else r"<form[^>]*>(.*?)</form>"
    match = re.search(pattern, page, re.S)
    if not match:
        return None, {}
    tag = re.search(r'<form[^>]*action="([^"]+)"', match.group(0))
    hidden = dict(re.findall(r'<input[^>]*type="hidden"[^>]*name="([^"]+)"[^>]*value="([^"]*)"', match.group(1)))
    return (html.unescape(tag.group(1)) if tag else None), hidden


def main():
    uri, code = sys.argv[1], sys.argv[2]
    user = os.environ.get("TRESOR_KC_USER", "alice")
    password = os.environ.get("TRESOR_KC_PASS", "alice-pass")
    # Keycloak marks its cookies Secure even over http, and sets one inside a redirect chain (the device flow's
    # restart cookie): a real browser treats 127.0.0.1 as a secure context and sends them - so does this policy
    class LoopbackIsSecure(http.cookiejar.DefaultCookiePolicy):
        def return_ok_secure(self, cookie, request):
            return True

    jar = http.cookiejar.CookieJar(policy=LoopbackIsSecure())
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

    current = [uri]  # the page's own URL: Keycloak's form actions may be relative

    def fetch(url, fields=None):
        data = urllib.parse.urlencode(fields).encode() if fields is not None else None
        response = opener.open(urllib.parse.urljoin(current[0], url), data=data, timeout=20)
        current[0] = response.geturl()
        return response.read().decode()

    def submit(action, fields):
        return fetch(action, fields)

    page = fetch(uri)
    # 1. the user code (skipped when the URI carried it: verification_uri_complete)
    if "device_user_code" in page:
        action, hidden = form_of(page)
        page = submit(action, dict(hidden, device_user_code=code))
    # 2. the login form
    action, hidden = form_of(page, "kc-form-login")
    if not action:
        print("device.py: no Keycloak login form after the user code", file=sys.stderr)
        return 1
    page = submit(action, dict(hidden, username=user, password=password, credentialId=""))
    # 3. a consent, when Keycloak asks for one
    if 'name="accept"' in page:
        action, hidden = form_of(page)
        page = submit(action, dict(hidden, accept="Yes"))
    if "Device Login Successful" not in page:
        print("device.py: the device login was not approved", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
