"""
Local dashboard server.

    sbc-validator serve [--results results] [--port 8787] [--host 127.0.0.1]

Serves the packaged dashboard viewer plus a live `dashboard_data.json` rebuilt
from the results directory on every request, so the fleet view refreshes as new
validate runs land. Pure stdlib, no framework.

Local-first by design: binds to 127.0.0.1 (loopback) by default, so the
dashboard never leaves the host unless the operator explicitly widens --host.
The raw configs never travel; only the already-local result JSON is read.
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources

from .tools.build_dashboard_data import build_payload


def _viewer_html() -> bytes:
    return (resources.files("sbc_validator.web") / "sbc_dashboard.html").read_bytes()


def _asset(name: str) -> bytes:
    # Serve only known, packaged static assets (no arbitrary path -> no traversal).
    return (resources.files("sbc_validator.web") / name).read_bytes()


def _make_handler(results_dir: str, anon: bool, org_salt: str):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, code, body, ctype):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = self.path.split("?", 1)[0]
            if path in ("/", "/sbc_dashboard.html"):
                self._send(200, _viewer_html(), "text/html; charset=utf-8")
            elif path == "/chart.umd.min.js":
                self._send(200, _asset("chart.umd.min.js"),
                           "application/javascript; charset=utf-8")
            elif path == "/favicon.ico":
                self._send(204, b"", "image/x-icon")   # browsers auto-request it; no-op
            elif path == "/dashboard_data.json":
                payload = build_payload(results_dir, anon=anon, org_salt=org_salt)
                if payload is None:
                    payload = {"fleet": [], "trend": {"labels": [], "series": {}},
                               "mode": "anon" if anon else "internal",
                               "ruleset_version": "unknown",
                               "_warnings": [f"no result files in {results_dir} yet "
                                             "(run: sbc-validator validate ... --out " + results_dir + ")"]}
                body = json.dumps(payload).encode()
                self._send(200, body, "application/json")
            else:
                self._send(404, b"not found", "text/plain")

        def log_message(self, *a):  # quiet by default
            pass

    return Handler


def run_serve(args) -> int:
    handler = _make_handler(args.results, getattr(args, "anon", False),
                            getattr(args, "org_salt", "unsalted"))
    httpd = ThreadingHTTPServer((args.host, args.port), handler)
    url = f"http://{args.host}:{args.port}/sbc_dashboard.html"
    mode = "anonymized" if getattr(args, "anon", False) else "internal"
    print(f"SBC Validator dashboard ({mode}) serving at {url}")
    print(f"  reading results from: {args.results}/   (live: rebuilds on every load)")
    print("  Ctrl-C to stop. Local-first: bound to "
          + ("loopback only" if args.host in ("127.0.0.1", "localhost") else args.host) + ".")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")
    finally:
        httpd.server_close()
    return 0
