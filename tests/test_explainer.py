"""Tests for the on-prem AI explanation layer (`explain --ai`).

Covers: correct class on every sample capture, the privacy gate (no raw
identifier survives tokenization), the never-override guardrail, the bundled
model artifact, and the CLI integration.
"""
import json
from pathlib import Path

from sbc_validator import cli
from sbc_validator.explainer import (
    CLASS_INFO, _MODEL_PATH, _Model, explain_capture, tokenize_call,
)
from sbc_validator.sip_trace import analyze

REPO = Path(__file__).resolve().parent.parent
SAMPLES = REPO / "samples"


def _ai(path):
    det = analyze(str(path))
    return explain_capture(str(path), det), det


def test_model_artifact_bundled():
    assert _MODEL_PATH.exists(), "bundled model missing from sbc_validator/data/"
    m = _Model.load()
    assert set(m.class_n) == set(CLASS_INFO)
    assert m.vocab_size > 0


def test_predicts_clean_call():
    blocks, _ = _ai(SAMPLES / "clean_call.pcap")
    assert len(blocks) == 1
    b = blocks[0]
    assert b["predicted_class"] == "CLEAN" and not b["suppressed"]


def test_predicts_codec_reject():
    blocks, _ = _ai(SAMPLES / "reject_488.pcap")
    b = blocks[0]
    assert b["predicted_class"] == "REJECT_488"
    assert b["domain"] == "E" and not b["suppressed"]


def test_predicts_one_way_audio():
    blocks, _ = _ai(SAMPLES / "one_way_audio.pcap")
    b = blocks[0]
    assert b["predicted_class"] == "ONE_WAY_AUDIO"
    assert b["domain"] == "D" and not b["suppressed"]


def test_predicts_topology_leak():
    blocks, _ = _ai(SAMPLES / "topology_leak.pcap")
    b = blocks[0]
    assert b["predicted_class"] == "TOPOLOGY_LEAK"
    assert b["domain"] == "F" and not b["suppressed"]


def test_privacy_no_raw_identifiers_in_tokens():
    """The air-gap guarantee: no IP, FQDN, or Call-ID survives tokenization."""
    from sbc_validator.pcap import read_packets
    from sbc_validator.sip_trace import _is_sip, _parse_sip
    pkts = read_packets(str(SAMPLES / "topology_leak.pcap"))
    msgs = [m for m in (_parse_sip(p) for p in pkts if _is_sip(p.payload)) if m]
    blob = " ".join(tokenize_call(msgs))
    for raw in ("80.0.0.10", "52.112.0.10", "10.9.9.9",
                "topo-leak-001@contoso.com", "contoso.com"):
        assert raw not in blob, f"raw identifier leaked: {raw}"


def test_guardrail_suppresses_on_disagreement():
    """If the deterministic diagnosis names a different domain, the AI block is
    suppressed: the model must never override the verdict."""
    det_fake = {"top_diagnoses": [{"domain": "C"}], "calls": []}
    blocks = explain_capture(str(SAMPLES / "reject_488.pcap"), det_fake)
    b = blocks[0]
    assert b["predicted_class"] == "REJECT_488"     # the model still predicts E
    assert b["suppressed"] and "suppressed" in b["note"].lower()


def test_cli_explain_ai_json(capsys):
    rc = cli.main(["explain", str(SAMPLES / "reject_488.pcap"), "--ai", "--json"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["ai_explanation"][0]["predicted_class"] == "REJECT_488"


def test_cli_explain_without_ai_unchanged(capsys):
    rc = cli.main(["explain", str(SAMPLES / "reject_488.pcap"), "--json"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert "ai_explanation" not in out
