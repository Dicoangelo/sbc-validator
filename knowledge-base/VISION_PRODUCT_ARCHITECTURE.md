# SBC Validator: Vision, Product, Architecture, Strategy (Master Synthesis)

This is the keystone knowledge document for the SBC Validator project. It
synthesizes the vision, the product, the technical architecture, the processes
and workflows, the build philosophy, the competitive landscape, the business
strategy, and the roadmap. Read this first; the other sources (docs, source
code, build history, tests/samples) are the ground truth beneath it.

---

## 1. One-line and elevator

**One line:** The independent truth layer for real-time voice. A local-first,
vendor-agnostic tool that validates Session Border Controller (SBC) configs
*before* deployment, predicts how a call would fail, and explains failures from
a packet capture.

**Elevator:** Enterprises run 50+ mixed-vendor SBCs (AudioCodes, Cisco, Ribbon,
Oracle) as the gatekeepers between their network and the outside world for
Microsoft Teams Direct Routing and SIP trunking. A single misconfigured SIP
header, certificate, or firewall rule takes the whole voice network down, often
for days. Modern NetDevOps automation (Terraform, Ansible, Itential) validates
Layer 3/4 flawlessly but is completely blind to Layer 5 (SIP/SDP) state-machine
logic. Every vendor tool is single-vendor (Cisco DNA, AudioCodes OVOC, Ribbon
LEAP) or post-deployment (AIOps watching MOS/jitter after the call drops). We
are the only multi-vendor, pre-deployment validation layer. "Ribbon LEAP, but
cross-vendor, before you hit commit."

## 2. Vision

Become the independent validation standard for real-time communications
infrastructure, the layer that sits outside the vendor and service-provider
chain and tells the truth about whether a config will work, across any vendor,
before it ships. Long term, as autonomous agents begin writing and deploying
network configs, the validator becomes the independent audit/truth layer that
checks what any actor (human or AI) is about to deploy. We never auto-push to a
production SBC; we are the check, not the deployer.

## 3. The problem (why this exists)

- **The SBC is a Back-to-Back User Agent (B2BUA).** Unlike a router that forwards
  packets, it fully terminates the external session and creates a brand-new
  internal session, translating between them (codec transcoding, SIP header
  manipulation, SRTP-to-RTP interworking). It is an air gap, two legs, not a pipe.
  This architecture is inherently hostile to CI/CD automation.
- **The Layer 5 blind spot.** L3/L4 validation is stateless formatting (allow IP X
  to port Y). L5 is a live, bidirectional, negotiated session. A mismatched SDP
  payload profile lets a call connect but destroys the audio; a one-character
  regex error in a header-rewrite rule kills a trunk silently. Generic tools
  cannot reason about this.
- **Multi-vendor reality.** Enterprises accumulate AudioCodes, Cisco, Oracle,
  Ribbon, Metaswitch, Ericsson, Nokia through mergers and history. No tool spans
  them; engineers translate logic across vendor silos by hand.
- **The forcing event: the 2026 Microsoft CA migration.** Every SBC's trust store
  must carry the current Microsoft root set or Teams calls hard-stop at the TLS
  handshake. serverAuth-EKU enforcement is live. This is a deadline-driven,
  cross-vendor certificate scramble with no proactive tooling.
- **MTTR of 1 to 4+ days** per misconfiguration; 80%+ of network outages stem from
  config/change management; BYOC (Bring Your Own Carrier) pushes SBCs into
  50-person firms whose "monitoring" is someone shouting that the phones are down.
- **Market is hidden by acronym dilution.** "SBC" also means Single Board
  Computers, an EA FC video-game cheat solver, and accounts-payable software, so
  generalist investors cannot see the whitespace.

## 4. The product (what runs today)

**Eight validation domains, on one normalized model, across four real vendor
parsers (AudioCodes, Cisco CUBE, Ribbon, Oracle Acme):**

- A: syntax/semantic baseline (malformed/inconsistent config).
- B: interop (TLS transport, OPTIONS keep-alive on both legs, normalization,
  IP-as-identity which Teams rejects with 403).
- C: TLS/CA wedge (root CAs, EKU, expiry, trust-anchor chain validation, SRTP,
  wildcard-aware CN/SAN matching). This is the 2026 forcing-event domain.
- D: NAT/media (one-way audio: private SDP IP, missing symmetric RTP).
- E: codec (Teams overlap, cross-leg transcode/DSP exhaustion, wideband downgrade).
- F: topology-leak (private-IP leakage on the signaling plane, from a pcap).
- G: routing/classification (404/unclassified Teams; both-direction routes).
- S: security/access-control (default-deny, broad CIDR, media-plane ACL omission,
  IPv6 neglect, RTP source validation).

**Three diagnostic modes** that speak the call flow, not config lint:
- **validate** (static audit producing a risk score + PASS/REVIEW/BLOCK verdict),
- **simulate** (deterministic, offline prediction of how far a call gets, naming
  the user-visible symptom and rendering a SIP ladder truncated at the failure),
- **explain** (packet-capture post-mortem: reconstructs the SIP ladder, detects
  one-way audio by RTP direction, maps each failure to its domain).

Plus: HA-drift `diff` (active vs standby), `fleet` readiness rollup ("X of N SBCs
ready for the 2026 CA migration"), a CI/CD gate (`validate --fail-on`), a local
dashboard (`serve`), an executive report (`report`), and a one-command `demo`.

## 5. Architecture

**Three planes:**
- Plane A, the product: the engine + local dashboard the CUSTOMER runs inside
  their VPC. ~done.
- Plane B: the signed-rule service the PUBLISHER runs (object storage / API; the
  client already speaks it). The rule bundles, not the code, carry the changing
  Microsoft requirements.
- Plane C: the consented anonymized telemetry aggregator, the data moat. Phase 2+.

**Key architectural choices (and why):**
- **Local-first / sovereignty.** The engine runs as a CLI/container inside the
  customer environment, fully air-gapped (`--network none` is provable). Raw
  configs never leave. The only inbound is a signed rule bundle; the only outbound
  is an opt-in, double-gated, anonymized findings payload. This turns the security
  review from an adoption blocker into the adoption wedge.
- **One normalized model.** Every vendor parser emits the same vendor-neutral
  NormalizedConfig; validators only ever see that model. This is what makes the
  validation genuinely vendor-agnostic, demonstrated, not asserted.
- **Signed, authority-sourced, rollback-floored rule channel.** Rule bundles are
  Ed25519-signed and verified against a pinned publisher key (private key offline,
  outside git); HTTPS-only transport; a freshness floor refuses a signed-but-stale
  bundle, because a valid signature on an out-of-date CA list would screen
  customers against the wrong roots. The seven Microsoft roots are sourced from
  Microsoft Learn with SHA-1 thumbprints and a documented re-sign workflow.
- **Deterministic, not LLM-in-the-verdict.** Parsers, validators, the call
  simulator, and the pcap explainer are all deterministic. The product's value is
  a verdict a customer acts on; an LLM that hallucinates "your trust chain is
  fine" is worse than no tool. AI is used for the plain-English explanation layer,
  not the verdict.
- **No external frameworks.** Pure stdlib plus one library (cryptography). The
  PCAP reader is dependency-free (no Wireshark/tshark/scapy). Lightness is the
  moat for a security-reviewed, air-gapped tool, not a shortcut.

## 6. Processes and workflows

- **Customer validation workflow:** export config -> `validate` (or air-gapped
  container) -> risk score + verdict -> optional `--html` report -> feed `--out`
  to `serve` for a live dashboard.
- **CI/CD shift-left gate:** `validate --fail-on review` returns a non-zero exit,
  dropping into a pipeline; a drop-in GitHub Action validates changed configs on
  every PR without the raw config leaving the runner.
- **Predict/validate/explain loop:** validate the config, simulate the call before
  deploy, explain the capture after, all in one shared domain vocabulary.
- **Rule re-sign workflow:** when Microsoft changes the CA list, re-source from
  Microsoft Learn, bump bundle_version, re-sign with the offline publisher key,
  run the authority-guard test, re-run the demo, commit (RULE_AUTHORITY.md).
- **Vendor onboarding workflow (the unlock):** obtain one real sanitized config
  per vendor -> model its real grammar -> light up routing (G) and security (S)
  for that vendor -> add it as a regression fixture. This is how AudioCodes became
  real (modeled against the Mediant manual).
- **Release workflow:** CI on every commit (3 Python versions + air-gapped Docker
  smoke); a `vX.Y.Z` tag publishes the container image to the registry.

## 7. Build philosophy (the discipline that is the moat)

- **Correctness by discipline.** When the source does not carry the information to
  judge something, the validator stays silent rather than guess. Routing, ACL, and
  the trust store all do this. A false "fix this" finding is the cardinal sin, it
  is worse than no tool. Concrete proof: an exact-match cert check was fixed to be
  wildcard-aware (it would have false-flagged the common wildcard Teams cert); and
  Cisco/Ribbon/Oracle ACLs are deliberately NOT mapped until their real grammar is
  modeled, because a naive map would false-fire.
- **Ground-truth before building.** Audit reality before writing code (the
  AudioCodes table parser was built against the real 1736-page Mediant manual).
- **Ship, then verify.** Small shippable increments; the end-to-end acceptance run
  (clean install + container) caught two real bugs unit tests missed.
- **Two-leg awareness.** The B2BUA has two legs; validate both, and name the gaps
  (carrier-leg ACLs, SRTP-RTP interworking) honestly.

## 8. Competitive landscape

- Cisco DNA: offline dial-plan emulation, Cisco-only.
- AudioCodes OVOC/ARM + config wizard: single-vendor; the wizard resets unmanaged
  parameters to factory defaults (a liability), unsupported in HA/IPv6.
- Ribbon LEAP: AI that learns live call flows, generates test scripts, claims 51%
  better coverage / 9.5x faster rollouts, Ribbon-only. The closest competitor; our
  pitch is "LEAP but cross-vendor."
- AIOps (e.g., Ribbon Analytics): post-deployment runtime observability (MOS,
  jitter, live logs). Zero pre-deployment validation. A smoke detector after the
  fire, not prevention.
- The whitespace: an independent, multi-vendor, pre-deployment Layer-5 simulator.
  Exactly our lane.

## 9. Business strategy

- **Wedge:** the 2026 Microsoft CA migration, a hard, dated, cross-vendor forcing
  event with no proactive tooling.
- **ICP question (a real strategic fork):** enterprise (50+ mixed-vendor SBCs, high
  value, slow procurement) vs BYOC SMBs (1 to 2 SBCs, no tooling, desperate, fast
  sale). BYOC may be the better beachhead; enterprise the expansion.
- **Moat:** the cross-vendor normalized model (hard to build), plus the consented,
  anonymized failure-pattern corpus across the industry, a benchmark no
  single-vendor tool can match (Plane C). The correctness discipline is also a
  moat: trust.
- **Patent whitespace (all framed as an external tool on a third-party SBC):**
  external SBC-tap deepfake detection; LLM SIP-ladder explanation from pcap;
  external PQC migration readiness scoring; multi-vendor config normalization with
  policy evaluation; out-of-band SHAKEN/PASSporT verification.
- **Commercial model:** per-SBC subscription with an explicit data-consent
  framework; the security-first architecture is also the pricing argument.
- **GTM:** 1 to 2 design-partner MSPs/enterprises with 50+ SBCs; advisory from
  Henning Schulzrinne (SIP co-inventor); Pindrop BD for the deepfake sidecar;
  channel via VARs/MSPs; category-capture talks at Kamailio World / OpenSIPS.

## 10. Roadmap and honest gaps

- **Proven today:** 4 vendors, 8 domains, signed authority-sourced rules, 126 tests
  in CI, air-gapped Docker, clean-install acceptance, 8 commands.
- **Gated (zero false positives until real configs):** routing (G) and security
  (S) for Cisco/Ribbon/Oracle; per-config cipher/mTLS matching; SRTP-RTP
  interworking. They stay silent for those vendors until modeled against ground
  truth.
- **Phase 2:** live SIP/TLS probing against a running SBC; deeper change-management
  integration; AI-assisted remediation with diff preview (engineer-applied, never
  auto-pushed).
- **Phase 3:** continuous drift monitoring; PQC readiness; deepfake-voice SIPREC
  sidecar; STIR/SHAKEN + Rich Call Data auditing; the telemetry data moat.
- **The single unlock:** one real, sanitized SBC config per vendor (CONFIG-REQUEST).

## 11. Team

Philip Drammeh (co-founder, telecom domain expert, ex-Microsoft
Telecom Spec Lead) and Dico Angelo (co-founder, AI builder/systems architect).
The product is built by Dico iterating with Claude (AI-assisted development),
grounded in Philip's domain expertise.
