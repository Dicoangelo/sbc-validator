"""Regression tests for the static demo dashboard build (the hosted visible layer).

This bundle broke twice in the field — once because the page was served without a
trailing slash (relative assets resolved to root) and once because the demo button
expected a live server. These tests lock in the fixes: the build emits all assets,
injects a <base> so relative refs survive the no-slash URL, leads with a standards-
mode doctype, and freezes a real multi-vendor demo payload + both walkthroughs.
"""
import json
import os
from pathlib import Path

from sbc_validator.tools import build_static_demo


def _build(tmp_path) -> Path:
    cwd = os.getcwd()
    root = Path(build_static_demo.__file__).resolve().parent.parent.parent
    out = tmp_path / "dashboard"
    try:
        rc = build_static_demo.build(out, root / "rulesets/ms_direct_routing_2026-06.json")
    finally:
        os.chdir(cwd)  # build() chdir's to repo root; don't leak that to other tests
    assert rc == 0
    return out


def test_emits_all_assets(tmp_path):
    out = _build(tmp_path)
    for name in ("index.html", "dashboard_data.json", "walk-broken.json",
                 "walk-fixed.json", "chart.umd.min.js"):
        assert (out / name).is_file(), f"missing {name}"


def test_index_is_standards_mode_with_base(tmp_path):
    # The two field regressions: Quirks Mode (no doctype) and the no-trailing-slash
    # URL (relative assets resolve to root without a <base>).
    html = (_build(tmp_path) / "index.html").read_text(encoding="utf-8")
    assert html.lstrip().lower().startswith("<!doctype html>")
    assert '<base href="/dashboard/">' in html


def test_demo_payload_is_real_and_multivendor(tmp_path):
    payload = json.loads((_build(tmp_path) / "dashboard_data.json").read_text())
    assert payload.get("mode") == "demo"
    fleet = payload["fleet"]
    vendors = {s["vendor"] for s in fleet}
    assert len(vendors) == 5, f"expected 5 vendors, got {sorted(vendors)}"
    assert "metaswitch_perimeta" in vendors
    # verdicts are the engine's own, not synthetic
    assert {s["summary"]["verdict"] for s in fleet} <= {"PASS", "REVIEW", "BLOCK"}


def test_walkthroughs_are_frozen_engine_output(tmp_path):
    out = _build(tmp_path)
    broken = json.loads((out / "walk-broken.json").read_text())
    fixed = json.loads((out / "walk-fixed.json").read_text())
    assert broken["which"] == "broken" and "BLOCK" in broken["output"]
    assert fixed["which"] == "fixed" and "PASS" in fixed["output"]


def test_base_path_is_configurable(tmp_path):
    cwd = os.getcwd()
    root = Path(build_static_demo.__file__).resolve().parent.parent.parent
    out = tmp_path / "custom"
    try:
        build_static_demo.build(out, root / "rulesets/ms_direct_routing_2026-06.json",
                                base_path="/preview/")
    finally:
        os.chdir(cwd)
    assert '<base href="/preview/">' in (out / "index.html").read_text(encoding="utf-8")
