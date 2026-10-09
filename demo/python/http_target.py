#!/usr/bin/env python3
"""Tiny HTTP/1.1 target and fake SSPanel `mod_mu` endpoint for the overtls demo suite.

Normal mode: answers every request with `200 OK`, `Connection: close` and `--body`.
Panel mode (`--panel --state FILE`): serves `GET /mod_mu/users` and
`POST /mod_mu/users/traffic`; `enable` is re-read from the state file on every request
(content "true"/"false"; missing file or anything else = false).
"""

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DEFAULT_CLIENT_ID = "11111111-1111-1111-1111-111111111111"


def make_handler(args):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *fmt_args):  # silence the default stderr logging
            pass

        def do_GET(self):
            self._dispatch("GET")

        def do_POST(self):
            self._dispatch("POST")

        def _respond(self, body):
            payload = body.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json" if args.panel else "text/plain")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            self.wfile.write(payload)

        def _dispatch(self, method):
            print(f"REQUEST {method} {self.path}", flush=True)
            if not args.panel:
                self._respond(args.body)
            elif self.path.startswith("/mod_mu/users/traffic"):
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                try:
                    parsed = json.loads(raw) if raw else {}
                except ValueError:
                    parsed = {"_unparsed": raw.decode("utf-8", "replace")}
                print("TRAFFIC " + json.dumps(parsed), flush=True)
                self._respond(json.dumps({"ret": 1, "data": {}}))
            else:
                enable = False
                try:
                    with open(args.state, "r", encoding="utf-8") as fh:
                        enable = fh.read().strip() == "true"
                except OSError:
                    enable = False
                data = [{"client_id": args.client_id, "enable": enable}]
                self._respond(json.dumps({"ret": 1, "data": data}))

    return Handler


def main():
    parser = argparse.ArgumentParser(description="HTTP target / fake mod_mu panel server")
    parser.add_argument("--port", type=int, default=0, help="TCP port to bind (0 = ephemeral)")
    parser.add_argument("--body", default="HTTP-TARGET-BODY", help="response body in normal mode")
    parser.add_argument("--panel", action="store_true", help="serve the fake panel instead")
    parser.add_argument("--state", help="file holding \"true\"/\"false\" (panel mode)")
    parser.add_argument("--client-id", default=DEFAULT_CLIENT_ID, help="client_id reported by the panel")
    args = parser.parse_args()

    if args.panel and not args.state:
        parser.error("--panel requires --state FILE")

    server = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(args))
    server.daemon_threads = True
    print(f"PORT {server.server_address[1]}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
