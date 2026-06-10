# Conviction Assessment — what we actually have
Generated 2026-06-10 | Session: sbc-autoops-validato-20260609-235604-69bb2b
Written gap-first, anti-hype, metric-backed. The job here is to separate earned
conviction from coherent-but-unproven hypothesis, so the loud parts stay honest.

---

## The one-sentence read
**The technology conviction is now very high and externally attested; the commercial
conviction is coherent but entirely unearned — and the whole risk has collapsed onto a
single door: landing the first design partner / consultancy that hands us one real
config per vendor.** Everything technical is de-risked. Everything commercial is a
hypothesis downstream of that one event.

---

## What is PROVEN (high conviction, earned, externally checkable)

1. **The whitespace is structural, not a timing accident.** The network-verification
   field's own survey enumerates ~19 named tools across data plane, control plane, and
   programmable data planes (Anteater, Veriflow, Batfish, Minesweeper, Tiramisu, Plankton,
   p4v...) and covers **zero** at Layer 5 / SIP / SBC. The discipline built expressly to
   verify config has provably never crossed into the application layer of real-time voice.
   This is the difference between "no competitor found" (weak) and "the field that would
   have built this has, by its own accounting, never built it" (strong). **Conviction:
   very high.** It is citable, not asserted.

2. **It is working software, not a deck.** 4 real vendor parsers on one normalized model,
   8 validation domains, 136 tests, air-gapped Docker, signed-rule channel, and a shipped
   on-prem AI explainer (`explain --ai`). You can run it. The 2026 ruleset exact-matches
   Microsoft's own published authority (7 roots + thumbprints, TLS 1.2, 4 ciphers).
   **Conviction: high** (verified by execution, not belief).

3. **The architecture is principled, and the literature is converging toward it AFTER we
   built it.** Our verdict is an adaptive consensus: 8 deterministic domain-experts, a
   risk-scorer that only ever escalates, and a learned signal that is structurally
   forbidden from overriding the deterministic council. The 2025 LLM-judge literature
   ("Beyond Consensus": LLM judges are 96% TP but <25% TN — they approve invalid things;
   "One Token to Fool LLM-as-a-Judge") independently discovered exactly why a learned
   signal must be subordinate. We named "a wrong PASS is worse than no tool" on day one;
   the field has now quantified the danger. **Conviction: high.** This is the ACE thesis
   instantiated, and it is defensible to a skeptical principal engineer.

4. **The moat-vs-AI contradiction is resolved with a verified build path.** The on-prem
   protocol-aware explainer keeps the air-gap intact while delivering the AI feature; the
   netFound substrate (open MIT weights) is confirmed downloadable. **Conviction: high on
   architecture, medium on execution** (the fine-tune is designed and corpus-proven, not
   yet trained on real data).

## What is REAL but UNPROVEN (coherent hypotheses, do not confuse with the above)

1. **The durable moat is still count ~1.** The whitespace is proven; defensibility-over-
   time is not built. The observability-semantics matrix (what a missing line means per
   vendor per firmware) needs real configs. A funded team that reads the same survey could
   start tomorrow; our lead is the cross-vendor model + correctness discipline +
   first-mover, not yet a data moat. **Honest status: the moat is a plan, not an asset.**

2. **Zero design partners. Zero revenue.** The consultancy-channel beachhead (eGroup /
   Server Consultancy / ChangePilot) is well-reasoned and the warm logic is sound, but not
   a single PO, pilot, or signed partner exists. Everything in the GTM is a forecast.

3. **The wedge timing is a narrative bet.** The hard 2026 CA deadlines largely passed; the
   "permanent cadence / cryptographic change management" reframe is intellectually correct
   and survives the survivor objection, but no customer has yet paid for the recurring
   framing rather than the expired deadline. Plausible, unvalidated.

4. **A dependency chain, not independent bets.** The flagship's real differentiation
   (netFound ceiling) needs real captures; real captures need the channel; the channel
   needs the first partner; the moat needs the same configs. **One unlock gates four
   outcomes.** That is leverage if it opens and a single point of failure if it doesn't.

## The danger to name out loud
The technical story is now strong enough to *mask* that there is no business yet. A
skeptical seed investor will grant the novelty and the engineering in the first ten
minutes, then ask the only question that matters: *"who has run this on a real fleet, and
what did they pay or promise?"* The honest answer today is "no one yet." The strength of
the convergence/whitespace narrative must not be allowed to paper over that. Conviction in
the artifact is not conviction in the company.

## Where the conviction actually points (the decision)
Everything de-risks or dies on **one real config per vendor from one real partner.** It is
simultaneously: the parser-fidelity unlock (C7), the moat seed, the flagship's training
set, the first revenue conversation, and the proof that the permanent-cadence framing
sells. The correct posture is therefore not "build more" — the build is already ahead of
the market — it is **"spend the technical credibility we have earned to open that one
door."** The convergence research (lineages A-D, the field survey, the ACE vindication) is
not academic decoration; it is the credibility instrument that gets the first serious
operator to take the call. Use it for that.

## Conviction, scored honestly (1-5)
| Dimension | Score | Basis |
|---|---|---|
| Novelty is real and defensible | 5 | field survey attests the L5 gap; nothing to argue |
| Product exists and works | 5 | 136 tests, runs air-gapped, ships explain --ai |
| Architecture is sound + principled | 5 | ACE consensus, literature-vindicated |
| Durable moat built | 2 | observability-semantics matrix at count ~1 |
| Market validated | 1 | zero partners, zero revenue, zero pilots |
| Path to validation is clear | 4 | one unlock (first config/partner) gates everything; channel identified |

**Net:** a 5-on-the-artifact, 1-on-the-market company whose entire trajectory is governed
by one well-understood unlock. That is a fundamentally healthy place to be — the hard,
un-fakeable part (a novel working system in a structurally empty space) is done — provided
we are disciplined enough to say the market half plainly and point all the earned
credibility at the single door that opens the rest.
