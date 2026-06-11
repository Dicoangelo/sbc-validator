"""
Local product surface (dashboard + scanner + walkthrough).

    sbc-validator serve [--results results] [--port 8787] [--host 127.0.0.1]

Serves the packaged single-page app, all views backed by the real engine:
  * Fleet       — live dashboard_data.json rebuilt from the results directory.
  * Scanner     — outside-in readiness probe (`POST /scan`), same engine as the public scanner.
  * Walkthrough — `GET /walk?which=broken|fixed` runs the real `walk` on the bundled
    samples and returns the actual staged output (ingest → validate → verdict → predict).
  * Findings    — fleet-wide filterable findings table (client-side over the payload).
  * Rule Bundles — `GET /bundle` provenance of the loaded signed ruleset.
  * Reports     — `GET /report` executive report (HTML, `?format=md` download) and
    `GET /report/sbc?name=` per-SBC report from the latest audit-trail JSON.
  * Setup Guide — wiring the validator into an estate (run paths, CI gate, artifacts).

Pure stdlib, no framework. Local-first: binds to 127.0.0.1 by default; raw configs
never travel. The scanner only touches public endpoints; the walkthrough only reads
the bundled sample configs.
"""
from __future__ import annotations

import contextlib
import io
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .tools.build_dashboard_data import build_payload

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_WALK_SAMPLES = {"broken": "sbc-teams-01-broken.ini", "fixed": "sbc-teams-01-fixed.ini"}


def _viewer_html() -> bytes:
    return (resources.files("sbc_validator.web") / "sbc_dashboard.html").read_bytes()


def _asset(name: str) -> bytes:
    # Serve only known, packaged static assets (no arbitrary path -> no traversal).
    return (resources.files("sbc_validator.web") / name).read_bytes()


def _samples_dir() -> Path:
    for cand in (Path("samples/walkthrough"),
                 Path(__file__).resolve().parent.parent / "samples" / "walkthrough"):
        if cand.is_dir():
            return cand
    return Path("samples/walkthrough")


def _walk_text(which: str, bundle) -> str:
    """Run the real `walk` on a bundled sample and return its staged text output."""
    name = _WALK_SAMPLES.get(which)
    if not name:
        return "unknown sample"
    if bundle is None:
        return "no ruleset available (the server could not load a signed bundle)"
    p = _samples_dir() / name
    if not p.is_file():
        return f"sample not found: {p}"
    from .parsers.audiocodes import detect_and_parse
    from .walk import walk_report
    cfg = detect_and_parse(p.read_text(encoding="utf-8", errors="replace"))
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        try:
            walk_report(cfg, bundle)
        except Exception as e:           # never 500 the demo
            buf.write(f"\n[walk error: {type(e).__name__}: {e}]\n")
    return _ANSI.sub("", buf.getvalue())


_demo_cache: dict = {}


def _demo_payload(bundle) -> dict:
    """The curated demo fleet, run through the REAL validators (not synthetic).
    Computed once per server process and cached; honest mode badge 'demo'."""
    if "payload" in _demo_cache:
        return _demo_cache["payload"]
    if bundle is None:
        return {"fleet": [], "trend": {"labels": [], "series": {}},
                "mode": "demo", "_warnings": ["no ruleset loaded"]}
    from .demo import _FLEET, _validate_one
    base = _samples_dir().parent          # samples/walkthrough -> samples/
    fleet = []
    for fname, site, vendor in _FLEET:
        p = base / fname
        if not p.is_file():
            continue
        try:
            cfg, findings, summary = _validate_one(p, bundle)
        except Exception:
            continue
        fleet.append({
            "sbc": cfg.sbc_fqdn or p.stem, "vendor": cfg.vendor, "site": site,
            "ruleset_version": bundle.get("bundle_version", "unknown"),
            "summary": summary,
            "findings": [{"check_id": f.check_id, "domain": f.domain or
                          f.check_id.split(".")[0], "severity": f.severity.name}
                         for f in findings],
        })
    payload = {"fleet": fleet, "trend": {"labels": [], "series": {}}, "mode": "demo"}
    if fleet:
        _demo_cache["payload"] = payload
    return payload


def _make_handler(results_dir: str, anon: bool, org_salt: str, bundle):
    from .scan_server import scan as _scan

    class Handler(BaseHTTPRequestHandler):
        def _send(self, code, body, ctype):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            u = urlparse(self.path)
            path = u.path
            if path in ("/", "/sbc_dashboard.html"):
                self._send(200, _viewer_html(), "text/html; charset=utf-8")
            elif path == "/chart.umd.min.js":
                self._send(200, _asset("chart.umd.min.js"),
                           "application/javascript; charset=utf-8")
            elif path == "/favicon.ico":
                self._send(204, b"", "image/x-icon")
            elif path == "/walk":
                which = parse_qs(u.query).get("which", ["fixed"])[0]
                body = json.dumps({"which": which,
                                   "output": _walk_text(which, bundle)}).encode()
                self._send(200, body, "application/json")
            elif path == "/dashboard_data.json":
                if parse_qs(u.query).get("demo", ["0"])[0] == "1":
                    return self._send(200, json.dumps(_demo_payload(bundle)).encode(),
                                      "application/json")
                payload = build_payload(results_dir, anon=anon, org_salt=org_salt)
                if payload is None:
                    payload = {"fleet": [], "trend": {"labels": [], "series": {}},
                               "mode": "anon" if anon else "internal",
                               "ruleset_version": "unknown",
                               "_warnings": [f"no result files in {results_dir} yet "
                                             "(run: sbc-validator validate ... --out " + results_dir + ")"]}
                self._send(200, json.dumps(payload).encode(), "application/json")
            elif path == "/report":
                # Consolidated executive report rendered live from the results dir.
                # ?format=md downloads the Markdown rendering of the same payload.
                payload = build_payload(results_dir, anon=anon, org_salt=org_salt)
                if payload is None:
                    body = ("<html><body style='font-family:system-ui;padding:40px'>"
                            "<h2>No results yet</h2><p>Run <code>sbc-validator validate "
                            "&lt;config&gt; --ruleset ... --out "
                            f"{results_dir}</code> and refresh.</p></body></html>").encode()
                    return self._send(200, body, "text/html; charset=utf-8")
                if parse_qs(u.query).get("format", ["html"])[0] == "md":
                    from .report.exec import render_markdown
                    body = render_markdown(payload).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/markdown; charset=utf-8")
                    self.send_header("Content-Disposition",
                                     'attachment; filename="sbc-exec-report.md"')
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("X-Content-Type-Options", "nosniff")
                    self.end_headers()
                    self.wfile.write(body)
                    return
                from .report.exec import render_html as _render_exec
                self._send(200, _render_exec(payload).encode(), "text/html; charset=utf-8")
            elif path == "/report/sbc":
                # Per-SBC report from the LATEST run JSON (the audit-trail artifact).
                if anon:
                    # the anonymized view tokenizes SBC names; per-SBC raw reports
                    # would leak the FQDNs that view exists to hide.
                    return self._send(403, json.dumps(
                        {"error": "per-SBC reports are disabled in the anonymized view"}
                    ).encode(), "application/json")
                name = parse_qs(u.query).get("name", [""])[0]
                base = Path(results_dir)
                # zero traversal surface: exact match against real directory entries
                entries = {p.name for p in base.iterdir() if p.is_dir()} if base.is_dir() else set()
                if name not in entries:
                    return self._send(404, b"unknown sbc", "text/plain")
                runs = sorted((base / name).glob("*.json"))
                if not runs:
                    return self._send(404, b"no runs for this sbc", "text/plain")
                from .report.html import render_html as _render_sbc
                report = json.loads(runs[-1].read_text())
                self._send(200, _render_sbc(report).encode(), "text/html; charset=utf-8")
            elif path == "/bundle":
                # Provenance of the loaded signed bundle (metadata only).
                if bundle is None:
                    return self._send(200, json.dumps(
                        {"error": "no signed bundle loaded"}).encode(), "application/json")
                import hashlib
                from .rules.client import _MIN_BUNDLE_VERSION, _PINNED_PUBLIC_KEY_B64
                meta = {
                    "ruleset_id": bundle.get("ruleset_id"),
                    "bundle_version": bundle.get("bundle_version"),
                    "issued_at": bundle.get("issued_at"),
                    "verified_on": bundle.get("verified_on"),
                    "source": bundle.get("source"),
                    "sources": bundle.get("sources"),
                    "domains": sorted(k for k in bundle
                                      if len(k) == 1 and isinstance(bundle.get(k), dict)),
                    "signature_present": bool(bundle.get("signature")),
                    "freshness_floor": _MIN_BUNDLE_VERSION,
                    "pinned_publisher_key_sha256":
                        hashlib.sha256(_PINNED_PUBLIC_KEY_B64.encode()).hexdigest()[:32],
                }
                self._send(200, json.dumps(meta).encode(), "application/json")
            else:
                self._send(404, b"not found", "text/plain")

        def do_POST(self):
            if urlparse(self.path).path != "/scan":
                return self._send(404, b"not found", "text/plain")
            try:
                n = int(self.headers.get("Content-Length", 0))
                payload = json.loads(self.rfile.read(n) or b"{}")
                fqdn = payload.get("fqdn", "")
            except (ValueError, json.JSONDecodeError):
                return self._send(400, json.dumps({"error": "bad request"}).encode(),
                                  "application/json")
            if bundle is None:
                return self._send(200, json.dumps(
                    {"error": "scanner unavailable: no ruleset loaded"}).encode(),
                    "application/json")
            self._send(200, json.dumps(_scan(fqdn, bundle)).encode(), "application/json")

        def log_message(self, *a):  # quiet by default
            pass

    return Handler


def _load_bundle(args):
    """Resolve the shipped (or --ruleset) signed bundle for /scan + /walk; None if absent."""
    try:
        from .cli import _load_ruleset, _resolve_ruleset
        rs = _resolve_ruleset(getattr(args, "ruleset", None))
        return _load_ruleset(rs) if rs else None
    except Exception:
        return None


def run_serve(args) -> int:
    bundle = _load_bundle(args)
    handler = _make_handler(args.results, getattr(args, "anon", False),
                            getattr(args, "org_salt", "unsalted"), bundle)
    httpd = ThreadingHTTPServer((args.host, args.port), handler)
    url = f"http://{args.host}:{args.port}/sbc_dashboard.html"
    mode = "anonymized" if getattr(args, "anon", False) else "internal"
    print(f"SBC-AutoOps console ({mode}) serving at {url}")
    print(f"  Fleet (reads {args.results}/) · Scanner (outside-in /scan) · "
          f"Walkthrough (live /walk){'' if bundle else '  [ruleset missing: scanner/walk disabled]'}")
    print("  Ctrl-C to stop. Local-first: bound to "
          + ("loopback only" if args.host in ("127.0.0.1", "localhost") else args.host) + ".")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")
    finally:
        httpd.server_close()
    return 0
