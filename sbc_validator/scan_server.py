"""
Public outside-in readiness scanner ("SSL Labs for SBCs").

    sbc-validator scan-serve [--port 8088] [--host 127.0.0.1]

Serves one static page (FQDN in, grade card out) plus a JSON `/scan` endpoint
that runs the `probe` engine server-side and grades the live TLS handshake
against the signed ruleset. Pure stdlib, zero new deps, host-agnostic (drop it
on Fly / Railway / a serverless shim later — it is just an HTTP handler).

Trust + safety for a PUBLIC endpoint:
  * No config is ever uploaded; only the FQDN, only public endpoints are touched.
  * SSRF guard: the FQDN is resolved and EVERY resolved address must be globally
    routable. Private / loopback / link-local / reserved targets are refused, and
    we connect to the validated IP (SNI = FQDN) so a DNS rebind cannot redirect us.
  * Basic per-IP rate limiting.
  * Anonymized logging: only the grade + coarse failure class, never the FQDN.
"""
from __future__ import annotations

import ipaddress
import json
import re
import socket
import time
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources

from .probe import SIP_TLS_PORT, default_connector, grade_endpoint

_FQDN_RE = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9](-?[a-zA-Z0-9])*\.)+[a-zA-Z]{2,}$")
_RATE_MAX = 12          # scans
_RATE_WINDOW = 60.0     # per this many seconds, per client IP


def _resolve_global(fqdn: str) -> str:
    """Resolve fqdn:5061; return one globally-routable IP. Raise ValueError if it
    does not resolve or ANY resolved address is non-public (the SSRF guard)."""
    try:
        infos = socket.getaddrinfo(fqdn, SIP_TLS_PORT, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise ValueError("does not resolve")
    chosen = None
    for _fam, _t, _p, _c, sa in infos:
        ip = ipaddress.ip_address(sa[0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                or ip.is_multicast or ip.is_unspecified):
            raise ValueError("resolves to a non-public address")
        chosen = chosen or sa[0]
    if not chosen:
        raise ValueError("no usable address")
    return chosen


def scan(fqdn: str, bundle: dict, connector=default_connector) -> dict:
    """Validate + grade one FQDN. The connector is injectable for offline tests;
    in production it is the hardened default that connects to the validated IP."""
    fqdn = (fqdn or "").strip().lower().rstrip(".")
    if not _FQDN_RE.match(fqdn):
        return {"error": "Enter a valid hostname, e.g. sbc.contoso.com"}
    try:
        ip = _resolve_global(fqdn)
    except ValueError as e:
        return {"error": f"Cannot scan {fqdn}: {e}."}
    hs = connector(fqdn, connect_host=ip)
    result = grade_endpoint(hs, fqdn, bundle)
    result["fqdn"] = fqdn
    return result


def _anon_log(log_path, result: dict) -> None:
    """Append only the grade + coarse failure classes. Never the FQDN/IP."""
    if not log_path:
        return
    rec = {
        "grade": result.get("grade"),
        "reachable": result.get("reachable"),
        "tls_version": result.get("tls_version"),
        "checks": sorted({i["check_id"] for i in result.get("issues", [])}),
    }
    try:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
    except OSError:
        pass


def stats(log_path) -> dict:
    """Aggregate the anonymized scan log into a 'State of SBC Readiness' summary.
    Reads only grades + check-IDs (the log never held an FQDN). Privacy-safe by
    construction: there is nothing identifying in the log to expose."""
    import os
    from collections import Counter
    out = {"total": 0, "reachable": 0, "grades": {}, "top_checks": []}
    if not log_path or not os.path.exists(log_path):
        return out
    grades, checks = Counter(), Counter()
    try:
        with open(log_path, encoding="utf-8") as f:
            for line in f:
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    continue
                out["total"] += 1
                if r.get("reachable"):
                    out["reachable"] += 1
                if r.get("grade"):
                    grades[r["grade"]] += 1
                for c in r.get("checks", []):
                    checks[c] += 1
    except OSError:
        return out
    out["grades"] = dict(grades)
    out["top_checks"] = [{"check_id": c, "count": n} for c, n in checks.most_common(8)]
    return out


def _page() -> bytes:
    return (resources.files("sbc_validator.web") / "scanner.html").read_bytes()


def _make_handler(bundle: dict, log_path):
    hits: dict[str, deque] = defaultdict(deque)

    class Handler(BaseHTTPRequestHandler):
        def _send(self, code, body, ctype):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def _client_ip(self) -> str:
            # Behind a proxy (Vercel/Fly), the real client is in X-Forwarded-For;
            # the first hop is the original client. Falls back to the socket peer.
            xff = self.headers.get("X-Forwarded-For", "")
            return xff.split(",")[0].strip() if xff.strip() else self.client_address[0]

        def _rate_ok(self) -> bool:
            ip = self._client_ip()
            now = time.monotonic()
            q = hits[ip]
            while q and now - q[0] > _RATE_WINDOW:
                q.popleft()
            if len(q) >= _RATE_MAX:
                return False
            q.append(now)
            return True

        def do_GET(self):
            path = self.path.split("?", 1)[0]
            if path in ("/", "/index.html"):
                self._send(200, _page(), "text/html; charset=utf-8")
            elif path == "/stats":
                self._send(200, json.dumps(stats(log_path)).encode(), "application/json")
            elif path == "/favicon.ico":
                self._send(204, b"", "image/x-icon")
            else:
                self._send(404, b"not found", "text/plain")

        def do_POST(self):
            if self.path.split("?", 1)[0] != "/scan":
                return self._send(404, b"not found", "text/plain")
            if not self._rate_ok():
                return self._send(429, json.dumps(
                    {"error": "Too many scans, please wait a minute."}).encode(),
                    "application/json")
            try:
                n = int(self.headers.get("Content-Length", 0))
                payload = json.loads(self.rfile.read(n) or b"{}")
                fqdn = payload.get("fqdn", "")
            except (ValueError, json.JSONDecodeError):
                return self._send(400, json.dumps({"error": "bad request"}).encode(),
                                  "application/json")
            result = scan(fqdn, bundle)
            if "error" not in result:
                _anon_log(log_path, result)
            self._send(200, json.dumps(result).encode(), "application/json")

        def log_message(self, *a):
            pass

    return Handler


def run_scan_serve(args) -> int:
    from .cli import _load_ruleset, _resolve_ruleset
    rs = _resolve_ruleset(getattr(args, "ruleset", None))
    if rs is None:
        print("error: no ruleset found; pass --ruleset <signed bundle>")
        return 2
    bundle = _load_ruleset(rs)
    handler = _make_handler(bundle, getattr(args, "log", None))
    httpd = ThreadingHTTPServer((args.host, args.port), handler)
    url = f"http://{args.host}:{args.port}/"
    print(f"SBC-AutoOps readiness scanner serving at {url}")
    print("  outside-in only: a live TLS handshake to the FQDN you enter; no config upload.")
    print("  SSRF-guarded (public targets only), rate-limited"
          + (f", anon log -> {args.log}" if getattr(args, 'log', None) else "") + ".")
    print("  Ctrl-C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")
    finally:
        httpd.server_close()
    return 0
