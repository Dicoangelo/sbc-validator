# Recursive Improvement Backlog

A living, candid self-assessment of the SBC Validator project, generated from the
end-to-end knowledge base (and refreshable by re-running the critical-analysis
query in NOTEBOOK-QUERIES.md). Read through the dual lens of a skeptical principal
engineer and a skeptical seed investor. The goal is to keep improving the product
and the business on a loop.

## 1. Technical risks and gaps

- **Silent false-negative blind spot (the cost of gating).** "Correctness by
  discipline" means routing (G) and security (S) are silent for Cisco, Ribbon, and
  Oracle (75% of vendors). A customer could get a PASS and deploy a wide-open
  Ribbon SBC because we could not parse its `ipAccessControlList`. The discipline
  is right, but the coverage gap is real and must be closed with real configs.
- **The deterministic ceiling.** Static analysis can verify a normalization
  profile is *present*, never that an arbitrary SIP-header regex is *correct*. A
  one-character typo still kills a trunk silently and we cannot catch it.
- **Carrier-leg under-validation.** The B2BUA has two legs; we are skewed to the
  Teams leg. Carrier-leg TLS posture is not inspected and SRTP-to-RTP interworking
  across legs is not modeled.
- **Unasserted crypto specs.** The signed ruleset carries the required TLS 1.2,
  SIP cipher allowlist, and SRTP suites, but the validator does not yet assert the
  config actually offers them per-config.

## 2. Product gaps

- **Topology-hiding on signaling is missing.** We catch private *media* IPs (D) but
  not internal IPs leaked in SIP Contact/Via/Record-Route/P-Asserted-Identity. A
  20-year vet expects topology hiding; it is a core SBC function.
- **Dashboard scaffolding.** The sidebar nav (Findings drill-down, Rule Bundles,
  Reports) is framing without real sub-pages. Acceptable as documented scaffolding,
  but to a technical buyer dead links read as a wireframe.
- **No ordered-ACL model.** Domain S flags broad CIDRs and missing default-deny but
  cannot detect top-down rule shadowing (a broad permit above a specific deny).
- **Onboarding friction.** Validation needs a manual, sanitized config export. For
  enterprises that is a high-friction adoption barrier.

## 3. Strategic and business risks

- **The ICP fork is being deferred.** BYOC SMB (fast, desperate, low volume) vs
  enterprise (50+ SBCs, slow procurement). The product is built enterprise-shaped
  (VPC-bound, fleet rollup), but enterprise cycles could outlast runway before the
  June-2026 EKU wedge. Decide the beachhead deliberately.
- **Moat durability.** The cross-vendor normalized model is the moat, but Ribbon
  LEAP claims big numbers and is AI-driven; if Microsoft ships its own pre-deploy
  Direct Routing checker, the wedge narrows. Lean into cross-vendor + the data moat.
- **Plane C is still vapor.** The anonymized failure-pattern data moat needs a
  consent framework and real customers generating data. No network effect yet.
- **Warm-channel GTM risk.** Parser fidelity depends on design-partner configs; if
  partners stall, the build stalls with them. Diversify the config-acquisition path.

## 4. Prioritized improvements (impact vs. effort, with first steps)

1. **Unblock Cisco/Ribbon/Oracle parsers** (high impact, low-med effort). First
   step: run the CONFIG-REQUEST campaign with a friendly partner for one real
   `show running-config` (Cisco) and `show configuration` (Ribbon).
2. **Plane-aware ACL mapping for domain S** (high impact, med effort). First step:
   map Ribbon `ipAccessControlList` to the AccessControlEntry model + regression
   tests; do NOT naive-map (steering-pools vs ipACLs differ).
3. **Topology-hiding leak detection** (high impact, med effort). First step: extend
   `sip_trace.py` to flag RFC1918 IPs in Contact/Via/Record-Route headers (domain F).
4. **Cipher-suite + mTLS assertion** (med impact, low effort). First step: expose
   the TLS context's offered suites and match against the ruleset allowlist.
5. **Scrub dashboard scaffolding** (med impact, low effort). First step: hide the
   sidebar links that have no sub-pages until they exist.
6. **SRTP-to-RTP interworking** (med impact, high effort). First step: a cross-leg
   media-security check in domain C (Teams SRTP vs carrier RTP).
7. **Ordered-ACL shadowing logic** (med impact, high effort). First step: make
   `access_controls` order-significant; flag a broad permit above a specific deny.
8. **Carrier-leg TLS posture** (med impact, med effort). First step: apply
   `cert_inspect.py` EKU/SAN/expiry to the carrier-leg cert.
9. **Stand up Plane B rule distribution** (med-low impact, med effort). First step:
   publish the signed ruleset to S3 / GitHub Releases; the HTTPS client already
   pulls + verifies + caches.

## How to keep this loop running

Re-run the "critical analysis" prompt in NOTEBOOK-QUERIES.md against the knowledge
base after each milestone. Feed new build history + docs back into the notebook so
the assessment stays current. The notebook is the recursive-improvement engine;
this file is its latest snapshot.

_Generated from the SBC Validator Project Knowledge Base (NotebookLM)._
