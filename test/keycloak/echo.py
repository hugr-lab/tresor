#!/usr/bin/env python3
"""An http API that answers who called it (specs/010): the `aud` and the user of the bearer token it received.

The token is not verified - Keycloak minted it; the test only reads whom it was minted for. Never prints the
token itself.

    echo.py --port-file PATH
"""
import argparse
import base64
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def answer(self, head):
        auth = self.headers.get("Authorization", "")
        claims = {}
        if auth.startswith("Bearer "):
            try:
                payload = auth[len("Bearer "):].split(".")[1]
                claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
            except Exception:
                claims = {}
        aud = claims.get("aud")
        aud = ",".join(sorted(a for a in aud if a != "account")) if isinstance(aud, list) else (aud or "none")
        body = ("aud=%s user=%s" % (aud, claims.get("preferred_username", "none"))).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if not head:
            self.wfile.write(body)

    def do_GET(self):
        self.answer(False)

    def do_HEAD(self):
        self.answer(True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port-file", required=True)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    with open(args.port_file, "w") as f:
        f.write(str(server.server_address[1]))
    server.serve_forever()


if __name__ == "__main__":
    main()
