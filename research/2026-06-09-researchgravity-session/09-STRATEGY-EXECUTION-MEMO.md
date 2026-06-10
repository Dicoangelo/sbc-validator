# Strategy Execution Memo — ready-to-apply copy + moves

Hands-off-the-live-site version: the parallel session owns `business-case.html`, so this is
**copy blocks + placement instructions** to apply there (or for me to apply once you hand me
the file). Each is grounded in `02-SYNTHESIS` and `00-SYNTHESIS` and respects the house
rules (no em dashes, zero external requests).

## 1. Re-anchor the hero: deadline -> permanent cadence
The deadline narrative expires on a calendar. Replace deadline-countdown framing with the
permanent category. Suggested hero lead + sub:

> **The independent truth layer for real-time voice.**
> Trust now rotates faster than telecom can keep up. We validate, before you deploy, that
> every SBC in your fleet survives the next certificate, cipher, and crypto change, across
> every vendor.

Category sentence (promote to hero-adjacent, it is the company in 13 words):
> You cannot monitor a call that is cryptographically blocked from ever starting.

## 2. Rebuild #crisis as a cadence, not a one-time event
Replace the single June countdown with the dated, third-party-verifiable schedule:
- TLS cert lifetimes compressing: **398 -> 200 days (Mar 2026) -> 100 (Mar 2027) -> 47 (by
  2029)** per the CA/Browser Forum. DR SBC certs are public-CA certs, so every fleet is hit,
  every cycle.
- **June 2026:** public CAs issue serverAuth-only server certs (Chrome Root Program v1.6).
- Scheduled PQC migration (NIST ML-KEM/ML-DSA finalized; SIP not yet started).
One line to land it: *"2026 was episode one. The trust regime keeps moving; this is the
layer that keeps your voice fleet in sync with it."*

## 3. Primary CTA -> the free scanner (once it is live)
Sequence the funnel: free outside-in grade -> shareable result -> inside-out upsell ->
design partnership. Make "Scan your edge free" the top CTA; demote "email us" to secondary.
(Coordinate timing with the scanner deploy you are shipping in the other session.)

## 4. Reconcile the trust-vs-data tension where the security reviewer reads
Near the air-gap pitch, add verbatim:
> Raw config and captures never leave your environment. Only opt-in, double-gated,
> anonymized findings leave (check IDs and severities, never config, IPs, FQDNs, or
> certificates). The failure pattern compounds across the industry; your configuration
> never does.

## 5. GTM: lead with the consultancy channel (Direction 2)
Outreach sequence, highest-leverage first:
1. **White-label to the consultancies already paid for MC1235747 remediation** — eGroup /
   Enabling Technologies, Server Consultancy (UK), ChangePilot. One PO, no enterprise
   security review, brings real configs in (closes C7), multiplies reach. Pitch: "your
   multi-vendor triage front-end for the cert migration and everything after it."
2. **Lighthouse design partner: TP ICAP** (AudioCodes + Cisco CUBE, MiFID II). The June
   serverAuth-EKU change points straight at Cisco CUBE estates. Frame as "install a control":
   name SBC-AutoOps the pre-deploy step in their audited change-management procedure.
3. **Post-incident, not preparedness:** Voipcloud / CallTower have fresh P1 scars and budget.
   Use the FusionConnect precision caveat (its failure was Microsoft-media-relay-side, not
   catchable from the customer config) so the pitch stays honest.

## 6. The single binding constraint (put it in every partner ask)
**One real, sanitized config per vendor.** It closes parser fidelity (C7), lights up routing
(G) + security (S) for Cisco/Ribbon/Oracle, and seeds the only durable moat (the
observability-semantics matrix). The consultancy channel produces it as a side effect, which
is why Direction 5 (channel) and the moat are the same move.

## 7. Flagship roadmap line (honest, from Track 2)
If you reference the AI explainer publicly, say it correctly: *"an on-prem SIP-capture
explainer that runs inside your air gap, never sending signaling data to a cloud model"* —
not "AI-powered." The on-prem framing is the differentiator AND the truth.
