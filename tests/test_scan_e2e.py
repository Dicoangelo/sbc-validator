"""End-to-end HTTP tests for the public scan server.

Boots the real ThreadingHTTPServer on an ephemeral loopback port and exercises
it over the wire: page serve, /stats aggregation, input validation, the SSRF
guard, and the per-IP rate limit. No external network: DNS is monkeypatched, so
no probe ever leaves the loopback.
"""
import json
import socket
import threading
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from sbc_validator.rules.client import RuleClient
from sbc_validator.scan_server import _RATE_MAX, _make_handler

REPO = Path(__file__).resolve().parent.parent


@pytest.fixture
def server(tmp_path):
    """A real scan server on an ephemeral port; yields its base URL."""
    bundle = RuleClient().fetch(
        "ms_direct_routing",
        local_path=str(REPO / "rulesets" / "ms_direct_routing_2026-06.json"))
    log = tmp_path / "scans.jsonl"
    log.write_text('{"grade":"A","reachable":true,"checks":[]}\n'
                   '{"grade":"FAIL","reachable":true,"checks":["C.CERT.EXPIRY"]}\n')
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(bundle, str(log)))
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        httpd.server_close()


def _get(url):
    with urllib.request.urlopen(url, timeout=5) as r:
        return r.status, r.read()


def _post(url, payload):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def test_e2e_page_and_stats(server):
    code, body = _get(server + "/")
    assert code == 200 and b"Direct Routing" in body
    code, body = _get(server + "/stats")
    s = json.loads(body)
    assert code == 200 and s["total"] == 2 and s["grades"]["FAIL"] == 1
    assert s["top_checks"][0]["check_id"] == "C.CERT.EXPIRY"


def test_e2e_scan_input_validation(server):
    code, d = _post(server + "/scan", {"fqdn": "not a hostname"})
    assert code == 200 and "error" in d
    code, d = _post(server + "/scan", {"fqdn": "localhost"})   # no dot -> rejected
    assert code == 200 and "error" in d


def test_e2e_ssrf_refused_over_the_wire(server, monkeypatch):
    """A hostname resolving to a private IP must be refused by the LIVE server.

    The patch only intercepts the scanned hostname; everything else (including
    urllib's own connection to the test server) resolves normally.
    """
    real = socket.getaddrinfo

    def fake(host, *a, **k):
        if host == "sbc.internal.example.com":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 5061))]
        return real(host, *a, **k)

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    code, d = _post(server + "/scan", {"fqdn": "sbc.internal.example.com"})
    assert code == 200 and "non-public" in d.get("error", "")


def test_e2e_rate_limit_429(server):
    """The per-IP limiter must return 429 once the window is exhausted."""
    codes = [_post(server + "/scan", {"fqdn": "x"})[0] for _ in range(_RATE_MAX + 1)]
    assert codes[-1] == 429 and codes[0] == 200
