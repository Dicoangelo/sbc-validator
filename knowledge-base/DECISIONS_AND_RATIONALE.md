# SBC Validator: Decisions and Rationale (ADR Log)

Why the project is built the way it is. Each decision records the choice, the
reasoning, and the consequence. These are the load-bearing judgments.

## D1. Local-first / air-gapped, not SaaS
**Choice:** the engine runs as a CLI/container inside the customer's environment;
raw configs never leave; it runs with `--network none`.
**Why:** the customers are MSPs/enterprises whose security teams reject any tool
that exfiltrates SBC config. The whole pitch is sovereignty. Hosting the engine
would destroy the value prop.
**Consequence:** the security review becomes the adoption wedge, not a blocker.
The dashboard stays local; the only legitimately hosted component is the
publisher-side signed-rule service (Plane B) and, later, the telemetry aggregator
(Plane C).

## D2. Deterministic verdicts, not an LLM in the decision path
**Choice:** parsers, validators, the call simulator, and the pcap explainer are
all deterministic. AI is used only for the plain-English explanation layer.
**Why:** the product's value is a verdict the customer acts on. An LLM that
hallucinates "your trust chain is fine" is worse than no tool. The market narrative
leaned on LLMs; the build deliberately did not, because determinism is the trust
story for this buyer.
**Consequence:** more defensible than an "AI guesses" tool; a competitor can also
call an LLM, but cannot easily replicate deterministic cross-vendor correctness.

## D3. Correctness by discipline: gate, don't guess
**Choice:** when the config source does not carry the info to judge something, the
validator stays silent (routing, ACL, trust store).
**Why:** a false "fix this" finding is the cardinal sin, worse than no tool, and it
destroys the credibility that is the moat.
**Consequence:** routing (G) and security (S) fire only for AudioCodes today;
Cisco/Ribbon/Oracle stay silent until their grammar is modeled against a real
config. Zero false positives in the meantime. Proven by the wildcard-cert fix
(exact match would have false-flagged a valid cert).

## D4. One normalized model
**Choice:** every vendor parser emits the same NormalizedConfig; validators never
see raw vendor syntax.
**Why:** this is the only way validation is genuinely vendor-agnostic, demonstrated
not asserted.
**Consequence:** the same A-G+S validators run unmodified across four vendors;
adding a vendor is a parser, not new validators.

## D5. Signed, authority-sourced, rollback-floored rule channel
**Choice:** rule bundles are Ed25519-signed, verified against a pinned key (private
key offline, outside git), HTTPS-only, with a freshness floor that refuses a
signed-but-stale bundle.
**Why:** a signature proves authenticity, not freshness. A validly-signed OLD
bundle (with the retired Baltimore root and no DigiCert G5) would screen customers
against the wrong CA list, worse than no tool. The roots are sourced from Microsoft
Learn with thumbprints.
**Consequence:** rule updates are decoupled from code releases (Plane B); a stale
or tampered bundle is refused cleanly, not with a traceback.

## D6. Rules ship through the signed channel, not the wheel
**Choice:** the ruleset is NOT bundled as package data in the Python wheel.
**Why:** bundling rules in the code would couple CA-list updates to code releases,
defeating the signed-rule design.
**Consequence:** `pip install` users fetch/point at a bundle; the container ships
one for convenience.

## D7. No external frameworks (pure stdlib + cryptography)
**Choice:** vanilla Python stdlib plus one library; the PCAP reader is
dependency-free (no Wireshark/tshark/scapy).
**Why:** every dependency is something a customer's security team must vet.
Lightness is the moat for an air-gapped, security-reviewed tool, and mirrors how
serious infra/security CLIs ship.
**Consequence:** the shortest possible security review; a clean wheel; an
air-gapped container verified in CI.

## D8. Predict / validate / explain, the "vet floor" pair
**Choice:** beyond static validate, ship `simulate` (predict the call) and
`explain` (pcap post-mortem), both deterministic and offline.
**Why:** a 20-year voice engineer thinks in call flows and user-visible symptoms,
not config lint. Speaking that language is the credibility bar.
**Consequence:** the tool surfaces temporal truth static severity cannot (a
clientAuth-only leaf is a quiet REVIEW today but a DEGRADED call under June-2026
EKU enforcement).

## D9. Never auto-push to a production SBC
**Choice:** AI-assisted remediation produces paste-ready snippets the engineer
applies; the platform never deploys.
**Why:** engineers will not trust automated pushes to live voice infrastructure.
**Consequence:** the long-term vision reframes the tool as the independent
audit/truth layer that validates whatever (human or AI) is about to deploy.

## D10. Ground-truth before building; ship then verify
**Choice:** model real grammar before writing parsers (AudioCodes built against the
1736-page Mediant manual); ship small increments; run end-to-end acceptance.
**Why:** documentation drifts; the failure modes live at the boundaries.
**Consequence:** the clean-install + container acceptance run caught two real bugs
unit tests missed (a tampered-ruleset traceback and a container permission crash).

## D11. The vendor-onboarding unlock is a real config, not more speculative code
**Choice:** stop building routing/ACL for Cisco/Ribbon/Oracle speculatively; ask
for one real sanitized config per vendor.
**Why:** each vendor's routing/ACL semantics differ enough that modeling blind
risks false verdicts (the cardinal sin). Real configs are the ground truth.
**Consequence:** CONFIG-REQUEST.md is the co-founder/partner action item that
converts gated domains to firing, the same path that made AudioCodes real.
