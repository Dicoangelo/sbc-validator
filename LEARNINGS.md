# SBC Validator: Learnings Knowledge Base

A living record of what we learned building SBC Validator: the domain, the
architecture, the per-vendor realities, and the working process. Append new
entries at the top of each section with a date. This is the onboarding doc for
anyone joining (Philip, future contributors) and the memory that keeps the
project coherent across sessions and tools.

Format for a learning: **what we learned -> why it matters -> how we apply it.**

---

## 1. Domain learnings (SBC / Direct Routing / the 2026 wedge)

- **(2026-06-07) Rule authority is the deepest risk, and our placeholder was
  wrong in the worst way.** When we sourced the real Microsoft list, the
  placeholder ruleset had listed BaltimoreCyberTrustRoot (the *retired* root) and
  MicrosoftRSARootCA2018 (not a real Teams DR root), and was *missing* the two new
  DigiCert G5 roots Microsoft is migrating onto. A customer running it would have
  been told to fix the wrong things while the tool stayed silent on the actual
  2026 gap. A confident PASS on a wrong rule set is worse than no tool.
  -> *Apply:* every rule is now sourced + thumbprinted + dated in
  [[RULE_AUTHORITY.md]], a test guards against any wrong-but-still-7 list, and we
  re-verify against Microsoft's live page before every pilot.

- **(2026-06-07) The authoritative 7 roots** (with SHA-1) are: DigiCert Global
  Root CA / G2 / G3, DigiCert TLS ECC P384 Root G5, DigiCert TLS RSA 4096 Root G5,
  Microsoft ECC Root CA 2017, Microsoft RSA Root CA 2017. Plus: TLS 1.2, a 4-cipher
  SIP allowlist, SRTP AES_CM_128_HMAC_SHA1_80, serverAuth-EKU enforced June 2026,
  test endpoint sip.g1.pstnhub.microsoft.com:5061. Source: Microsoft Learn.

- **(2026-06-07) Real-world identifier matching must be tolerant.** Trust stores
  name the same CA inconsistently ("Certificate Authority" vs "CA", spaces, case).
  We normalize + fold that synonym + accept SHA-1 thumbprints. This is a parser-
  fidelity win as much as a CA-list win: the tool now matches what real configs
  actually write, not just our canonical spelling.


- **The 2026 Microsoft CA migration is a hard, dated forcing function.** Trust
  stores must carry all required Microsoft/DigiCert root CAs before Microsoft
  rotates onto them (remediation deadline ~end Feb 2026, rotation from April 2026,
  full enforcement ~June 2026). The failure mode is a hard TLS handshake stop:
  calls do not connect and Teams shows nothing pointing at the cert. That is the
  "scream test" the product prevents.
  -> *Apply:* domain C (TLS/CA) is the wedge. Lead every artifact with it.

- **One-way audio is the #1 customer complaint and is almost always NAT/media.**
  The SBC advertises a private/non-routable address in SDP, or lacks symmetric
  RTP, so media from NATed peers never returns.
  -> *Apply:* domain D checks advertised-address routability + symmetric RTP.

- **The serverAuth-EKU deprecation is a second, quieter CA-era trap.** Dual-use
  and clientAuth-only TLS server leaves are being deprecated (Chrome Root
  Program). A leaf that "worked" can silently lose trust.
  -> *Apply:* domain C flags missing serverAuth EKU (HIGH) and dual-use (LOW).

- **Existing tools are vendor-locked (AudioCodes OVOC, Ribbon RAMP) or
  post-deployment monitors.** The pre-validation layer at Layer 5 (SIP/SDP) is an
  open gap. That gap is the whole company.

- **Verdicts need three states, not two.** PASS / REVIEW / BLOCK. REVIEW (a HIGH
  with no CRITICAL) is the common real-world case; collapsing it into pass/fail
  loses the most useful signal. Any CRITICAL forces BLOCK.

---

## 2. Architecture learnings

- **The normalized model is the entire moat.** Every vendor parser emits one
  `NormalizedConfig`; validators only ever see the normalized form, never raw
  vendor syntax. This is what makes "vendor-agnostic" real instead of a slide.
  Proven at N=3 (AudioCodes, Cisco CUBE, Ribbon): the five A-E validators run
  unchanged across all three.
  -> *Apply:* never let vendor specifics leak into a validator. If a check needs
  vendor knowledge, that knowledge belongs in the parser, mapped onto the model.

- **Validators are pure functions of (config, ruleset) -> findings.** No I/O, no
  network, no shared state. Trivial to test, trivial to reason about, trivial to
  add domains.

- **Rules are the only thing that crosses the trust boundary, so treat bundles as
  untrusted-until-verified.** Bundles are versioned + Ed25519-signed against a
  pinned publisher key; tampered bundles are rejected before use; the verified
  version is stamped into every report ("freshness assertion"). Configs never
  travel this channel. Only rules come in; only opt-in anonymized findings go out.
  -> *Apply:* the security review becomes the adoption wedge, not a blocker.

- **The trust boundary is a single explicit switch (`--anon`).** Internal payload
  = FQDNs + sites + full detail, stays inside the customer. Anonymized payload =
  check_id + severity + domain + vendor + ruleset version + salted org token,
  safe to aggregate cross-tenant. Anonymized export is double-gated
  (`--share-anon` AND `--consent`).
  -> *Apply:* the consented, anonymized failure-pattern dataset is the long-term
  data moat.

- **Truth beats declaration: inspect real cert material when present.** Domain C
  reads EKU/SAN/expiry/chain from the actual PEM and lets it override
  config-declared values. Falls back gracefully if `cryptography` is missing or a
  file is unreadable.

- **Exit codes make it a CI gate.** The CLI returns non-zero on BLOCK, so the same
  tool drops straight into a pre-deployment pipeline (Phase 2).

---

## 3. Per-vendor parser learnings

- **Start one vendor end-to-end, then widen. Do not build four shallow parsers at
  once.** AudioCodes first proved the model held; Cisco and Ribbon then dropped in
  against the same validators. This sequencing is the reason the model is clean.

- **Trust is expressed completely differently per vendor, yet maps to the same
  field.** AudioCodes lists root CAs as `trusted_roots = A, B, C`. Cisco creates a
  `crypto pki trustpoint <Name>` per trusted CA (so every non-identity trustpoint
  IS a trusted root id). Ribbon uses `set system security pki certificate <Name>
  type remote`. All three normalize to `TlsContext.trusted_root_ids`.
  -> *Apply:* the C root-CA check is shaped around an enumerable root set. New
  vendors must populate `trusted_root_ids` however their config expresses trust.

- **Config grammars vary wildly; pick the parsing strategy per vendor.**
  AudioCodes = INI sections (`configparser`). Cisco CUBE = indented IOS-XE blocks
  (custom block walker). Ribbon = flat `set <path> <value>` lines (token split).
  The normalized model absorbs all three.

- **Running-configs often can't show everything (e.g. leaf EKU on Cisco/Ribbon).**
  We use an annotated-export convention (`# sbc-validator: leaf-cert <path>`) to
  point at the exported PEM, so the deep cert pass has real material instead of
  guessing. Honest about the limitation; pragmatic about the workaround.

- **HA drift compares failover-critical fields, NOT node identity.** FQDNs and
  media IPs legitimately differ between active and standby; transport, mTLS, trust
  store, keep-alive, normalization, codecs, DTMF must match. Trust-store drift is
  CRITICAL because a failover during the 2026 rotation lands on a node with an
  incomplete trust set and calls hard-stop. (HA drift ties back to the C wedge.)

---

## 4. Process learnings (how we work)

- **Ground-truth before claiming.** Every "it works" in this project is backed by
  a clean-extract run: untar -> fresh venv -> `pip install` -> `pytest` -> `demo.sh`.
  Catches packaging bugs (missing files) that a working dev copy hides. A working
  dev tree is not evidence the artifact ships.

- **Tag build status honestly: [Operational] vs [Roadmap].** Every capability in
  every doc is tagged. The fastest way to lose a technical buyer (or a co-founder)
  is to let a roadmap item read as shipped. Honesty is the credibility asset.

- **Hand-in-hand Code <-> Desktop loop.** Dico moves the project between Claude
  Code (build/verify) and Claude Desktop (review/narrative). Each pass reconciles
  the other: Desktop aligned the dossier to code; Code then proved the claims and
  extended them. Leave explicit "next pass" notes so the loop stays coherent.

- **Do not fabricate demo data.** We deliberately did NOT synthesize a multi-day
  dashboard trend, because a fake downward trend in a pitch is dishonest. Honest
  capability beats a prettier chart.

- **Vendor count is the credibility unlock.** The single highest-leverage build
  was the second (then third) vendor parser: it converts "vendor-agnostic" from an
  assertion into a demonstration. Prioritize the proof over polish.

- **Customer-facing artifacts inherit the writing rules.** The HTML report is a
  customer artifact, so it gets the same scrub as prose (caught an em dash in a
  remediation string). Escape all user/config-derived values in generated HTML.

- **Each iteration is a clean, diffable checkpoint** (V4 -> V5 -> V6 folders, each
  with a CHANGELOG). Cheap to compare, easy to roll back, clear provenance.

---

## 5. Key decisions log

| Decision | Choice | Why |
|---|---|---|
| Deployment model | Local-first (CLI/container in customer VPC) | Removes the raw-config-exfiltration objection that kills security reviews |
| Remediation | Suggest + diff preview, engineer applies | Engineers will not trust auto-push to production SBCs |
| Verdicts | PASS / REVIEW / BLOCK | REVIEW is the common real case; two states lose signal |
| Rule distribution | Signed (Ed25519) + versioned, pinned pubkey | Rules are the only inbound channel; must be untrusted-until-verified |
| Telemetry | Off by default, double-gated, anonymized only | Consent-based failure-pattern moat without exfiltration risk |
| First vendor | AudioCodes end-to-end | Prove the model before widening |
| Cert handling | Inspect real PEM, override config | Truth beats declaration |

---

## 6. Open questions / next

- **Root-CA names in the ruleset are operator-curated placeholders.** The 7-count
  and serverAuth-EKU rule are verified; the exact CA identifiers must be confirmed
  against Microsoft's Azure Certificate Authority details page and the bundle
  re-signed before a real pilot.
- **Demo leaf certs are self-signed fixtures.** Next C deepening: trust-anchor
  chain validation against a configured root store (verify the chain terminates at
  a trusted anchor, not just that it is unbroken).
- **4th vendor: Oracle/Acme** (currently a stub). Needs a real sample export.
- **Phase 2:** remote signed-rule transport (resolve + cache + verify is in place;
  the HTTP call is the TODO); CI/CD integration (the exit-code gate already works).
- **Master pitch dossier** still reads single-vendor; refresh on the next Desktop
  pass (focused one/two-pager + slides are current as of V6).
