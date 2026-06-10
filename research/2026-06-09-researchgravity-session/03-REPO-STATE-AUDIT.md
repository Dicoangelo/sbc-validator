# Repo State Audit — ground truth vs. claims

Verified 2026-06-09 against the working tree at commit `b7a2073` (HEAD). Method: read the
code/docs, run `pytest --collect-only`, grep the site. The point of this file is to
separate what is *built and proven* from what is *claimed or stale*, so the next session
(and Philip) inherit truth, not drift.

## Verified true (built + proven)

| Claim | Verification |
|---|---|
| v0.16.1 | `pyproject.toml` version = 0.16.1 |
| 4 vendor parsers on one normalized model | `sbc_validator/parsers/` = audiocodes, cisco_cube, ribbon, oracle; all feed `models.py` |
| 8 validation domains live | `sbc_validator/validators/` = A/B/C(ca_compliance)/D(nat_traversal)/E(codec)/ha_drift/G(routing)/S(access_control); F via pcap |
| Deterministic, no LLM in verdict | parsers + validators + call_sim + pcap reader all deterministic |
| Air-gapped (`--network none`) | Dockerfile + README; validate path has no network calls |
| Ed25519 signed rule channel | `rules/client.py` pinned public key; offline signer in `tools/` |
| Ruleset = Microsoft-authoritative | insight 11: 7 roots + thumbprints + TLS 1.2 + 4 ciphers + SRTP suite EXACT-match MS Learn |
| 8 CLI commands | validate / simulate / explain / diff / fleet / serve / demo / report (+ probe, scan-serve) |
| 126 tests green | `pytest --collect-only` = **126 collected** |
| Site is air-gap-consistent | business-case.html: 0 em-dashes, 0 external runtime requests |

## Stale / drifted (fix before expert review)

| Drift | Where | Truth |
|---|---|---|
| "100 tests" | README.md, REVIEW-FINDINGS.md status line | now **126** |
| "104 tests" | Philip `_READ-ME-FIRST.md`, reviewed commit 2259540 | HEAD is `b7a2073`, 126 tests |
| Intermediate counts 113 / 118 / 123 / 126 | insights 00 / 08 / 11 | 126 is current; the lower numbers are time-stamped snapshots, fine as history but the **forward-facing docs (README, Philip packet) should say 126** |
| Reviewed commit 2259540 vs HEAD b7a2073 | Philip packet was rendered at 2259540 | 5 commits landed since (OPTIONS-interval, E.DTMF.INBAND_TEAMS, probe cert-identity, grounded checks). If Philip meets after these, re-render or note the delta |

## Known gates (honest, by design — not bugs)

- Routing (G) + security (S) stay **silent** for Cisco / Ribbon / Oracle until modeled
  against a real config (C7). This is correct discipline, but it means a PASS on those
  vendors is "no opinion," not "clean." Say so out loud.
- Per-config cipher/TLS-version assertion: the ruleset carries the values; the C.TLS
  checks were built across all 4 parsers per insight 00, but verify H5's remaining
  per-config assertion scope.
- SRTP-to-RTP cross-leg interworking: unmodeled.

## Verify-before-meeting checklist (1 sweep, ~15 min)
1. `report/risk.py` — confirm the H4 score-gate actually shipped (16 MEDIUMs must NOT
   print "Verdict PASS"). Insight 00 claims commit 3ecd00a; confirm in code.
2. Bump test-count in README.md + Philip `_READ-ME-FIRST.md` to 126 (or auto-generate it).
3. Confirm `git tag` — RUNBOOK's `docker pull ghcr.io/...:latest` primary-install path
   needs a published image; D6 in REVIEW-FINDINGS flags zero tags shipped an image. There
   are now tags v0.16.0 / v0.16.1 — confirm the image actually published, or demote the
   pull instruction to "build locally."
4. Re-render the Philip packet from HEAD if the meeting is post-`b7a2073`.

## Archive disposition
The Desktop `SBC ARCHIVE` (Configurator V4/V5/V6, docx drafts) is correctly marked
superseded. It oversells (SaaS / multi-agent AI verdicts / auto-remediation). Keep as
historical reference; **never source a capability claim from it.** BUSINESS-CASE-SPEC's
"Honesty reconciliation" table is the canonical correction.
