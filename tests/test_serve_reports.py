"""End-to-end HTTP tests for the serve console's post-run delivery routes.

Boots the real local console server (serve._make_handler) on an ephemeral
loopback port over a synthetic results directory and exercises:
  * /report          - consolidated executive report (HTML + Markdown download)
  * /report/sbc      - per-SBC report from the latest audit-trail JSON,
                       traversal-proof, gated off in the anonymized view
  * /bundle          - signed-bundle provenance metadata
"""
import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from sbc_validator.rules.client import RuleClient
from sbc_validator.serve import _make_handler

REPO = Path(__file__).resolve().parent.parent


def _run(sbc: str, verdict: str, ts: str) -> dict:
    return {
        "sbc": sbc, "vendor": "audiocodes", "site": "lab",
        "ruleset_version": "2026-06-07", "validated_at": ts,
        "summary": {"risk_score": 100 if verdict == "BLOCK" else 0,
                    "verdict": verdict,
                    "counts": {"CRITICAL": 1 if verdict == "BLOCK" else 0,
                               "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}},
        "findings": ([{"check_id": "C.CA.ROOT_MISSING", "domain": "C",
                       "severity": "CRITICAL", "title": "roots missing",
                       "detail": "2 of 7 Microsoft roots missing",
                       "remediation": "import the G5 pair"}]
                     if verdict == "BLOCK" else []),
    }


def _results_dir(tmp_path) -> str:
    d = tmp_path / "results"
    for sbc, verdict, ts in [
        ("sbc01.contoso.com", "BLOCK", "2026-06-10T01:00:00+0000"),
        ("sbc01.contoso.com", "BLOCK", "2026-06-11T01:00:00+0000"),
        ("sbc05.fabrikam.com", "PASS", "2026-06-11T01:00:00+0000"),
    ]:
        run = _run(sbc, verdict, ts)
        sub = d / sbc
        sub.mkdir(parents=True, exist_ok=True)
        stamp = ts.replace(":", "").replace("-", "").replace("+0000", "Z")
        (sub / f"{stamp}.json").write_text(json.dumps(run))
    return str(d)


def _bundle():
    return RuleClient().fetch(
        "ms_direct_routing",
        local_path=str(REPO / "rulesets" / "ms_direct_routing_2026-06.json"))


def _serve(results_dir, anon=False, bundle=None):
    httpd = ThreadingHTTPServer(
        ("127.0.0.1", 0),
        _make_handler(results_dir, anon, "salt", bundle))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://127.0.0.1:{httpd.server_address[1]}"


def _get(url):
    with urllib.request.urlopen(url, timeout=5) as r:
        return r.status, dict(r.headers), r.read()


@pytest.fixture
def live(tmp_path):
    httpd, base = _serve(_results_dir(tmp_path), bundle=_bundle())
    try:
        yield base
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_exec_report_html(live):
    code, headers, body = _get(live + "/report")
    assert code == 200 and "text/html" in headers["Content-Type"]
    text = body.decode()
    assert "sbc01.contoso.com" in text or "2 SBCs" in text or "Executive" in text


def test_exec_report_markdown_download(live):
    code, headers, body = _get(live + "/report?format=md")
    assert code == 200
    assert "text/markdown" in headers["Content-Type"]
    assert "attachment" in headers.get("Content-Disposition", "")
    assert b"Executive Report" in body


def test_per_sbc_report_latest_run(live):
    code, headers, body = _get(live + "/report/sbc?name=sbc01.contoso.com")
    assert code == 200 and "text/html" in headers["Content-Type"]
    assert b"C.CA.ROOT_MISSING" in body  # latest run content rendered


def test_per_sbc_traversal_is_dead(live):
    for evil in ("../../etc", "..%2F..%2Fetc", "sbc01.contoso.com/../..", ""):
        with pytest.raises(urllib.error.HTTPError) as e:
            _get(live + "/report/sbc?name=" + evil)
        assert e.value.code == 404


def test_per_sbc_blocked_in_anon_view(tmp_path):
    httpd, base = _serve(_results_dir(tmp_path), anon=True, bundle=_bundle())
    try:
        with pytest.raises(urllib.error.HTTPError) as e:
            _get(base + "/report/sbc?name=sbc01.contoso.com")
        assert e.value.code == 403
        # the consolidated report still works (it renders the anonymized payload)
        code, _, _ = _get(base + "/report")
        assert code == 200
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_bundle_provenance(live):
    code, headers, body = _get(live + "/bundle")
    assert code == 200 and "application/json" in headers["Content-Type"]
    meta = json.loads(body)
    assert meta["bundle_version"] >= "2026-06-07"
    assert meta["signature_present"] is True
    assert meta["freshness_floor"] >= "2026-06-07"
    assert "C" in meta["domains"]
    assert len(meta["pinned_publisher_key_sha256"]) == 32


def test_report_empty_results_is_friendly(tmp_path):
    httpd, base = _serve(str(tmp_path / "nothing"), bundle=None)
    try:
        code, headers, body = _get(base + "/report")
        assert code == 200 and b"No results yet" in body
        code, _, body = _get(base + "/bundle")
        assert json.loads(body)["error"].startswith("no signed bundle")
    finally:
        httpd.shutdown()
        httpd.server_close()


# ---- drag-and-drop validate (POST /validate, OPS-004) ----------------------

def _post(url, body: bytes, ctype="text/plain"):
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": ctype})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_validate_good_config_returns_verdict(live):
    cfg = (REPO / "samples" / "walkthrough" / "sbc-teams-01-broken.ini").read_bytes()
    code, d = _post(live + "/validate", cfg)
    assert code == 200
    assert d["ok"] is True
    assert d["verdict"] == "BLOCK"          # broken Teams config -> blocked
    assert d["vendor"] == "audiocodes"
    assert d["report"]["findings"]          # findings present
    assert d["report"]["call_prediction"]["outcome"] == "NO_CONNECT"
    assert "<!doctype html>" in d["html"].lower()   # reuses the HTML renderer


def test_validate_fixed_config_passes(live):
    cfg = (REPO / "samples" / "walkthrough" / "sbc-teams-01-fixed.ini").read_bytes()
    code, d = _post(live + "/validate", cfg)
    assert code == 200 and d["verdict"] == "PASS"


def test_validate_malformed_config_is_clean_error(live):
    # No vendor parser matches -> a clean one-line error, never a 500/traceback.
    code, d = _post(live + "/validate", b"this is not any SBC vendor config\n")
    assert code == 200
    assert "error" in d and "ok" not in d
    assert "Traceback" not in d["error"]
    assert d["error"]  # non-empty human-readable message


def test_validate_empty_body_rejected(live):
    code, d = _post(live + "/validate", b"")
    assert code == 400 and "error" in d


def test_validate_unavailable_without_bundle(tmp_path):
    httpd, base = _serve(str(tmp_path / "x"), bundle=None)
    try:
        code, d = _post(base + "/validate", b"[ Teams ]\n")
        assert code == 200 and "error" in d and "ruleset" in d["error"]
    finally:
        httpd.shutdown()
        httpd.server_close()
