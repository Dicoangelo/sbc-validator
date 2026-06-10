# Findings — logged to RG global in a DEDICATED, CONTAINED session

**Final arrangement (Dico's call, 2026-06-09/10):** RG-global logging is fine; the
project stays contained. A dedicated standalone RG session
**`sbc-autoops-validato-20260609-235604-69bb2b`** was created (no `--impl-project`
link to any existing project) and all SBC findings live there. The earlier accidental
write into the shared `frontier-alpha-r&d-d` session was retracted (backup:
`~/.agent-core/session_tracker.json.bak.2026-06-09-pre-sbc-retract`; that session is
back to its pre-existing 15 findings, untouched).

**Six findings logged to the contained session** (full text in the RG session store;
summarized below + in this folder's docs):
1. Wedge-decay resolved: deadline -> permanent cadence (Finding 1 below).
2. Durable moat = observability-semantics matrix, count ~1 (Finding 2 below).
3. Beachhead ICP = consultancy channel (Finding 3 below).
4. Prior-art + competitor sweep: whitespace confirmed; LLMcap/PLUME/netFound resolve
   the air-gap-vs-AI tension (see `06-PRIOR-ART-AND-COMPETITORS.md`).
5. Flagship shipped (2026-06-10, commit 397add1): `explain --ai` on-prem explanation
   layer in the product, 136 tests (see `07-ONPREM-EXPLAINER-POC.md` + repo).
6. ML lesson: synthetic corpora teach timing artifacts; fixed with class-independent
   gap jitter + cross-distribution regression tests (the generalizable training rule
   for the future netFound fine-tune).

> NOTE: the shared `frontier-alpha` session already contained 15 SBC-flavoured findings
> from 2026-05-27 (the original positioning + innovation-frontier research) BEFORE this
> session. That pre-existing mixing is flagged as a recommendation below; this session did
> not touch those 15.

---

## Finding 1 — Wedge-decay resolved (deadline -> permanent cadence)
The Microsoft 2026 Direct Routing CA migration is a one-time deadline (hard root-CA cutoff
Mar 31 passed; serverAuth-EKU "Effective June 2026"), so the "beat the deadline" narrative
is falsifiable by a calendar. Resolution: re-anchor to a PERMANENT category, "cryptographic
change management for real-time voice." Durable cadence = CA/Browser Forum cert-lifetime
compression (398 -> 200 days Mar 2026 -> 100 Mar 2027 -> 47 by Mar 2029; DR SBC certs are
public-CA certs so every fleet is hit) + scheduled PQC migration + continuous Chrome Root
Program tightening. Each enforcement wave = a new signed rule bundle on the same
deterministic engine = the subscription thesis. The signed rule feed IS the business
(antivirus-definitions model).

## Finding 2 — Durable moat metric is the observability-semantics matrix, count ~1
NOT the parsers (LLMs collapsed parser cost to a 6-12 month asset). The durable moat is the
observability-semantics matrix (what a MISSING config line means per vendor per firmware),
which only real configs build; today that count is ~1 (only AudioCodes hardened against a
real Mediant .ini). REVIEW-FINDINGS C1/C7 shows it is still an IOU. The air-gap trust model
self-cancels the data moat. Two moves: (1) outside-in free scanner bootstraps an anonymized
benchmark corpus without touching configs; (2) "install a control", get regulated partners
(MiFID II/FINRA/CJIS) to name SBC-AutoOps as the mandated pre-deploy step in their audited
change-management procedure. Controls do not churn.

## Finding 3 — Beachhead ICP is the consultancy channel
The fastest converter is the consultancy channel, not BYOC-SMB or enterprise direct.
eGroup/Enabling Technologies, Server Consultancy (UK), ChangePilot are ALREADY paid to do
Microsoft MC1235747 remediation and have NO multi-vendor tool. A small white-label license
closes on one PO (no enterprise security review), brings real end-customer configs in
(closing C7 / the G+S coverage gap on 75% of vendors), and multiplies reach. Lighthouse
lead: TP ICAP (AudioCodes + Cisco CUBE, MiFID II). Post-incident selling (Voipcloud /
CallTower, with the FusionConnect media-relay caveat) beats preparedness selling.

---

## Recommendation on RG independence (do NOT auto-execute)
1. Keep all SBC research in this in-repo folder (`research/`), not in `~/.agent-core` RG
   sessions. This folder travels with the product git and stays sovereign to the project.
2. If you ever DO want SBC in ResearchGravity, open a **dedicated** session
   (`sbc-autoops-<date>`), never the `frontier-alpha` session, and consider migrating the
   15 pre-existing SBC findings out of `frontier-alpha` into it so the shared corpus is
   clean. This is a suggestion only; not done.
