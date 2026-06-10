# ResearchGravity Session — SBC-AutoOps / SBC Validator

**Date:** 2026-06-09 (deep_night, peak hour)
**Operator:** Dico Angelo + Claude (Opus 4.8)
**Protocol:** ResearchGravity full session (cold-start, retrieval, synthesis, log-back)
**Subject:** `~/projects/sbc-validator` (GitHub: Dicoangelo/sbc-validator, private)
**Reviewed build:** v0.16.1 @ commit `b7a2073`, 126 tests green

This folder is the complete log and synthesis of one ResearchGravity protocol session
run across the full repo, the supporting local archives, and the live marketing site.
No source was modified by this session (read-only audit); three findings were logged
back into the ResearchGravity corpus.

## Contents

| File | What it is |
|---|---|
| `00-SESSION-LOG.md` | Chronological protocol log: every step, query, and tool call |
| `01-SOURCE-INVENTORY.md` | Every source ingested and its evidentiary role (repo / archive / Philip review / vault / RG corpus / site) |
| `02-SYNTHESIS.md` | **The keystone deliverable.** Thesis -> Gap -> Innovation Direction, in the ResearchGravity format |
| `03-REPO-STATE-AUDIT.md` | Ground-truth of what is actually built vs. claimed (incl. the doc-drift on test count) |
| `04-MARKETING-SITE-AUDIT.md` | State of `marketing/business-case.html` against its own spec |
| `05-RG-FINDINGS-LOGGED.md` | The findings logged to RG (in a dedicated, contained SBC session — not merged into any existing project) |
| `06-PRIOR-ART-AND-COMPETITORS.md` | **Deep prior-art sweep:** academic papers (LLMcap / PLUME / netFound) + the full commercial competitor matrix + patent FTO flags + whitespace confirmation |
| `07-ONPREM-EXPLAINER-POC.md` | **Track 2:** design for the flagship on-prem (air-gap-consistent) SIP-capture AI explainer |
| `08-PATENT-FTO-BRIEF.md` | **Track 4:** founder-prepared freedom-to-operate brief for IP counsel (2 HIGH claims + design-arounds) |
| `09-STRATEGY-EXECUTION-MEMO.md` | **Track 4:** ready-to-apply site copy + GTM moves (cadence re-anchor, consultancy channel) |
| `artifacts/explainer-poc/` | **Track 2:** runnable protocol-aware SIP tokenizer (`sip_tokenizer.py`, passes privacy + structure self-tests) + POC README |

## Execution log (2026-06-09/10 build session)
After the research synthesis, all four "fill the vital gaps" tracks were executed:
- **Track 1 (code correctness): DONE.** H4 score-gate verified shipped; `is_blocking()` aligned; ghcr.io image pipeline live (D6 resolved); test-count drift fixed to **126** across 8 docs + the site; full Philip packet rebuilt at HEAD. 126 tests green.
- **Track 3 (scanner web UI): owned by the parallel session** (user's other terminal shipped scan_server + scanner.html + Vercel/Fly + site wiring). Not duplicated, to avoid file collision.
- **Track 2 (on-prem explainer): DONE (POC).** Design doc + runnable SIP tokenizer.
- **Track 4 (strategy + FTO): DONE.** FTO brief + strategy-execution memo (copy handed off for the parallel session to apply to the live site).

## One-paragraph conclusion

SBC-AutoOps is a genuinely differentiated, technically honest product (4 vendors, 8
domains, deterministic verdicts, air-gapped, signed-rule channel, 126 tests) sitting
on a real but **expiring** wedge. The single most important strategic move is already
identified and partly executed in the repo's own `marketing/insights/`: re-anchor from
the one-time 2026 Microsoft CA deadline to the permanent category of **cryptographic
change management for real-time voice**, sell **through the consultancy channel** that is
already paid to do the remediation, and convert the **free outside-in scanner** into the
data-moat bootstrap that the air-gap model otherwise starves. The binding constraint on
all of it is unchanged since 2026-05-27: **one real sanitized config per vendor**
(CONFIG-REQUEST), which simultaneously closes the parser-fidelity gap (C7) and seeds the
only durable moat (the observability-semantics matrix).
