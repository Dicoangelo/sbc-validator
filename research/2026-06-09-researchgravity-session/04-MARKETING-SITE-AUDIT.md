# Marketing Site Audit — business-case.html

File: `marketing/business-case.html` (72 KB, single self-contained page). Built from
`BUSINESS-CASE-SPEC.md`. Audited 2026-06-09. Deploy is HELD per standing instruction.

## Structure (section map)
top -> why -> crisis (the cadence/forcing-event) -> how -> demo -> proof -> cost ->
outcomes -> regulated -> market -> model -> roadmap -> team -> cta. Plus an interactive
config-diff layer (`tg-broken` / `tg-fixed`, `cd-*`, `cdlive`) and progress/tilt/reveal
animation hooks. This matches the project's "battle stations must ship a live interactive
layer" rule.

## Verified clean (the trust-model proofs)
| Check | Result |
|---|---|
| Em-dashes | **0** (house rule satisfied) |
| External runtime requests | **0** (only outbound is the portfolio href `dicoangelo.metaventionsai.com`; fonts self-hosted in `marketing/fonts/`) |
| Self-hosted fonts | 28 woff2 subsets, local `@font-face` via `fonts.css` |
| CTA wired | `mailto:dicoangelo@metaventionsai.com`; 3 internal `#cta` anchors incl. one inside `#demo` (the peak-conviction ask) |
| Hero | "The independent [truth layer for real-time voice]" |
| Internal anchors | all resolve to real section ids (no broken jumps) |
| Demo/scanner/probe/verified language present | 37 mentions |

The page is, literally, a working demo of the trust model: a security reviewer can open
the network tab and see zero external requests. Keep it that way.

## Open editorial decisions (from insight 00, still live)
1. **Category sentence placement.** "You cannot monitor a call that is cryptographically
   blocked from ever starting" is the company in 13 words. Insight 00 marks it promoted to
   hero-adjacent (commit 09d7d66); confirm it reads in the hero, not buried in `#why`/`#proof`.
2. **Trust-vs-data-corpus reconciliation** must sit where the security reviewer reads
   (near the air-gap pitch): "raw config never leaves; only opt-in anonymized findings
   (check IDs + severities, never config/IPs) leave. The pattern compounds; your
   configuration never does." Insight 00 says reconciled in moat03; verify it is visible
   on the page, not only in the spec.
3. **Cadence framing live?** `#crisis` should now lead with the permanent cadence
   (cert-lifetime compression schedule), not a one-time June countdown. Confirm the
   countdown sub-copy is retargeted to the June-2026 window and labelled as episode one.
4. **Mobile.** Insight 00 flagged the 820px media query hiding the header CTA on small
   screens and no `<noscript>` fallback. Verify both before go-live.

## Recommended gate before deploying a URL
Per insight 00 and the standing hold: **one human review pass (Dico + Philip)**, then a
single mobile + network-tab check. The page is technically ready; the hold is a judgment
gate, not a defect gate.

## The one content move this synthesis adds
If Direction 1 (re-anchor to permanent cadence) and Direction 3 (free scanner) are the
strategy, the page's primary CTA should arguably evolve from "email us for a design
partnership" to **"scan your edge free"** (the outside-in scanner) as the top-of-funnel
ask, with the design-partner email as the secondary/qualified CTA. That sequences the
funnel: free grade -> shareable result -> inside-out upsell -> design partnership. Hold
until the scanner front-end ships (the `probe` engine already exists).
