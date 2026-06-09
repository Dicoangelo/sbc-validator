# SBC Validator: Deep Self-Audit Findings (pre-expert review)

Generated 2026-06-09 from a five-agent deep code review (Claude Fable 5), a
second pass after the initial DeepSeek review. Each agent read its area
line-by-line and reproduced bugs by executing code, not by inspection alone.

This is our own adversarial audit. We publish it so the outside expert reviews a
product that already knows its own weak spots and has a fix plan with priorities.

The organizing theme: the codebase invented the right discipline ("silence beats
a wrong verdict": when a source does not carry the info to judge something, stay
silent) and applied it well in domains G and S and on the leaf-cert path, but
applied it **inconsistently**. Most CRITICAL findings are places where one half
of the code forgot a rule the other half enforces.

Severity: CRITICAL = wrong verdict or demo-killer in front of an expert.
HIGH = a claim/gap the expert names in the first hour. MEDIUM/LOW = correctness
debt. Each item carries the originating agent finding ID for traceability.

## Status (2026-06-09) — fixed on branch `review-hardening`

Tests 79 -> 100; the canonical demo fleet verdicts are unchanged throughout; the
wheel ships the vendored Chart.js so the air-gapped dashboard works offline.

- **FIXED** Doc drift + em dashes (D1-D7, E1).
- **FIXED** C3 simulate: expired/self-signed/untrusted cert now hard-stops TLS.
- **FIXED** C2 trust store: empty + introspectable is CRITICAL, not LOW.
- **FIXED** C5/C6 explain: TLS close_notify no longer false-flags; one-way-audio
  uses reverse-flow + RTCP exclusion + port keying.
- **FIXED** S1/S2/S3 security: dashboard XSS escaped; compiled-in freshness floor
  (clean install + cache fallback); dashboard vendored air-gapped (no CDNs).
- **FIXED** H3 ordered-ACL shadowing (S.ACL.SHADOWED_DENY / SHADOWED_PERMIT).
- **FIXED** C4 internal media realm no longer false-BLOCKs (MediaRealm.role).
- **FIXED** H4 is_blocking() aligned to the verdict mapping.
- **FIXED** H1 HA drift: normalized + introspectable-gated trust-store compare,
  plus HA.DRIFT.SRTP (SV-11).
- **FIXED** H6/H7/H8/F12 pcap engine: Linux SLL2 captures, IPv4 fragmentation,
  IP total-length padding, SIP 487/481/491 caller-clearing (not config faults).
- **FIXED** H9 cross-signed chain: subject->list, follow the candidate whose
  signature verifies (no false CHAIN_INVALID / UNTRUSTED_ANCHOR).
- **FIXED** crash battery (partial): non-dict signed bundle rejected cleanly (the
  reproduced traceback); parser faults were already exit-2 via the CLI boundary.
- **FIXED** C1 tristate foundation + AudioCodes table parser now emits None (not
  guessed False) for unresolved SRTP/keep-alive.
- **FIXED** M1 DTMF severity inversion; F11 cert-expiry UTC comparison.
- **REMAINING** H5 cipher/TLS-version assertion (dormant without parser support;
  docs already frame it as roadmap). C1's remaining parser-honesty work for the
  simple AudioCodes parser + Cisco/Ribbon/Oracle, and encoding the demo samples'
  intended "off" states, are gated on **C7 parser fidelity** (a real customer/Wizard
  config per vendor) so the honest-None behaviour can be validated against ground
  truth rather than guessed on synthetic samples. M2/M3 (codec canonicalization,
  IPv6-neglect severity) deferred as they need a real config or a severity decision.

---

## CRITICAL — wrong verdict / demo-killer

### C1. Tristate collapse: "unknown" is stored as "off" (SV-01, P-GD-1)
`models.py`: `SipInterface.transport`, `options_keepalive`, `srtp_enabled`,
`TlsContext.mtls_enabled`, `MediaRealm.symmetric_rtp`, `Certificate.chain_complete`
are plain `bool = False` / falsy, not `Optional`. A parser that cannot observe a
value emits the falsy default, and the validator reads that default as a real
"off/missing" finding. Confirmed from the parser side: all four parsers hardcode
`mtls_enabled=True` and `chain_complete=True` (permanently silencing two CA
checks) while emitting `srtp_enabled=False` / `transport="udp"` on lookup misses
(fabricating HIGH findings). A clean AudioCodes SBC whose `.ini` does not textually
carry SRTP/EKU/transport gets 3-5 HIGH findings and a wrong REVIEW verdict.

This is the exact product-killing failure the design principle exists to prevent.
The model authors already proved the fix pattern: `teams_classified: Optional[bool]`,
`rtp_source_validation: Optional[bool]`, and `TlsContext.introspectable`.

**Fix:** tristate every observability-sensitive field (`Optional`, default `None`);
every consuming check guards `is False` / `is not None`; parsers assign only when
the construct was actually observed and read the real source field
(`SIPInterface_TLSMutualAuthentication`, Ribbon `authClient`, Oracle
`mutual-authenticate`, Cisco trustpoint chain) instead of hardcoding.

### C2. Empty trust store rated LOW instead of CRITICAL (SV-02)
`ca_compliance.py`: when `trusted_root_ids` is empty the code emits LOW
"verify out-of-band" and skips the missing-roots check **without consulting
`introspectable`**. A Ribbon/Oracle export that fully enumerates its trust store
and shows zero roots is a guaranteed mTLS hard-stop during the 2026 CA rotation,
the single scenario this product is sold to catch, and the tool reports LOW and
may PASS. The leaf-cert path 70 lines up does the `introspectable` branch
correctly; the trust-store path does not.

**Fix:** branch on `introspectable`. Not introspectable -> LOW out-of-band.
Introspectable and empty -> CRITICAL `C.CA.ROOT_MISSING` (0 of 7). Symmetrically,
suppress the false CRITICAL when `introspectable=False` but a partial list leaked.

### C3. simulate predicts STABLE on an expired / self-signed / untrusted cert (F1)
`call_sim.py`: the stage maps omit `C.CERT.EXPIRY` (CRITICAL), `C.CERT.SELF_SIGNED`,
`C.CERT.CHAIN_INVALID`, `C.CERT.UNTRUSTED_ANCHOR`, `B.SIP.IDENTITY_IS_IP`,
`D.MEDIA.NO_REALM`. An expired certificate (the most classic Direct Routing
outage) produces a CRITICAL finding yet `simulate` prints "STABLE: two-way audio",
contradicting the tool's own findings list printed beside it. First thing a vet
tests.

**Fix:** add the cert hard-stops to `_TLS_HARDSTOP`; make stage mapping
severity-aware so `(C.CERT.EXPIRY, CRITICAL)` hard-stops while MEDIUM
expiring-soon warns. Regression test: expired-cert fixture -> `NO_CONNECT`,
dies at TLS handshake.

### C4. Every media realm judged public-facing -> false BLOCK (SV-03)
`nat_traversal.py` + `models.py`: `MediaRealm` carries no role/leg. The
public-advertisement test runs on all realms, so a correct internal/LAN realm
advertising an RFC1918 address triggers CRITICAL `D.NAT.PRIVATE_ADVERTISED` ->
BLOCK; and `advertised_public_ip is None` fires HIGH even when `local_ip` is itself
globally routable (a public-interface DMZ SBC needs no advertised address). The
textbook two-realm topology gets BLOCKed.

**Fix:** add a role/interface association to `MediaRealm`; run D only on the
Teams/public realm; treat `advertised_public_ip is None` as fine when `local_ip`
is global; stay silent when neither address is in the source.

### C5. TLS close_notify false-flags every clean session as a failed handshake (F2)
`sip_trace.py`: `tls_alert` matches any TCP segment on 5061 whose first byte is
`0x15`. A graceful TLS 1.2 shutdown sends close_notify as a content-type-0x15
record, so every healthy session that closes cleanly trips the
"handshake failed, untrusted root CA" diagnosis; and the check runs per-segment
(no record framing), so mid-stream ciphertext hits `0x15` ~1/256 segments. This is
the headline `top_diagnoses` entry mapped to the 2026 CA wedge.

**Fix:** per-flow state in capture order; treat `0x15` as a handshake alert only
before any application-data (`0x17`) record on that flow; validate the record
header; decode plaintext fatal alerts (level/description) and report the real
alert code (a vet will value "fatal alert 48 unknown_ca").

### C6. One-way-audio detection arithmetic is wrong (F3)
`sip_trace.py`: `rtp_flows` keyed by `(src_ip, dst_ip)` globally; one-way declared
via distinct source-IP count < 2, not reverse-flow presence. Two unrelated one-way
flows read as two-way; a healthy call masks another call's one-way audio; the
verdict is stamped on every connected call; `_looks_rtp` matches RTCP and ~25% of
DNS so a stray packet flips the verdict. Marquee `explain` use case.

**Fix:** per-flow reverse check `any((d,s) not in flows for (s,d) in flows)`;
correlate flows to the call SDP `c=` addresses already parsed; exclude RTCP
(PT 200-204); require a minimum packet count; key by (ip,port).

### C7. Real Mediant `.ini` and real CUBE configs are mis-parsed (P-AC-1, P-CU-1)
The AudioCodes table-ini parser was built against the synthetic sample grammar and
misses real-export realities: scalar `[SYSTEM Params]` sections treated as tables,
prefixed FORMAT columns (`IPGroup_Name`), table-name casing (`[ IpProfile ]`),
coder tokens (`g711Ulaw64k`). The Cisco parser never reads dial-peers, where
Microsoft's reference CUBE config puts the Teams `session target ...pstnhub...`,
`srtp`, and `options-keepalive`. On a perfectly configured customer SBC both
degrade the Teams leg into a misjudged carrier leg or "no Teams interface".

**Status:** this is the known parser-fidelity gate. It is gated honestly (we do not
claim Cisco/Ribbon/Oracle routing+ACL), but the AudioCodes real-format claim is
overstated until a real Wizard/customer `.ini` hardens it. **This is the #1 ask of
Dico/Philip** (CONFIG-REQUEST.md). The tristate fix (C1) removes the false
*positives*; real configs remove the false *negatives*.

---

## HIGH — named by the expert in the first hour

### Security
- **S1. Stored XSS in the fleet dashboard** (sec #1). `web/sbc_dashboard.html`
  interpolates `s.sbc`, `s.vendor`, `s.site`, `s.top`, check IDs into
  `insertAdjacentHTML` with no escaping; these come straight from the customer
  config FQDN/site. The server-rendered reports escape correctly; the dashboard
  does not. Fix: a JS `esc()` on every dynamic value, or build nodes via
  `textContent`.
- **S2. Freshness floor not enforced by default** (sec #2). The rollback floor is
  `max(SBC_RULE_MIN_VERSION, cached_version)`; on a clean install with the env
  unset the floor is empty and any validly-signed but years-old bundle (the
  retired-Baltimore CA list) is accepted. The cache-fallback path skips
  `_reject_rollback` entirely. Fix: bake a `_MIN_BUNDLE_VERSION` constant beside
  the pinned key; apply the floor in the cache branch too.
- **S3. "Air-gapped" dashboard loads Chart.js + Google Fonts from CDNs** (sec #3),
  no SRI. Contradicts the `--network none` claim and is a supply-chain/MITM
  surface on the security tool's own UI. Fix: vendor the assets into `web/` and
  serve them locally.

### Validators / model
- **H1. HA trust-store drift uses raw string compare, ignores `introspectable`**
  (SV-04). Same root named two ways across firmware -> false CRITICAL BLOCK; a
  non-introspectable standby reads as "empty" -> false drift. Fix: shared `_norm()`
  on both sides; LOW out-of-band when either context is missing/non-introspectable.
- **H2. Default-deny evaluated globally, not per IP version/plane** (SV-05). An
  IPv6 plane with permits but no `::/0` deny passes silently. Fix: compute
  `has_default_deny` per version (and plane).
- **H3. Ordered-ACL shadowing not detected** (SV-06, also flagged by parsers).
  `access_controls` is treated as an unordered set, so a `permit 0.0.0.0/0` above
  the deny-all (everything admitted) and a carrier permit below the deny-all
  (trunk blackholed) both look healthy. Fix: walk in order per plane/version, flag
  any rule fully covered by an earlier opposite-action rule; `permit any` -> HIGH.
- **H4. Verdict and risk score can contradict** (SV-07). Verdict keys only on
  HIGH/CRITICAL presence; a config with 16 MEDIUMs scores ~96 but PASSes on the
  same line. `Finding.is_blocking()` (HIGH => blocking) also contradicts the
  verdict mapping (HIGH => REVIEW). Fix: a score-threshold gate (>=40 => at least
  REVIEW); align `is_blocking()` with the real mapping.
- **H5. No TLS-version or cipher/SRTP-suite assertion** (SV-12, P-GD). The signed
  ruleset carries TLS 1.2, the SIP cipher allowlist, and the SRTP suite, but domain
  C never asserts the config offers them. The remediation text names a suite the
  product never checks. Fix: add `min_tls_version` / `srtp_crypto_suites` to the
  model (tristate, silent on None), driven from the ruleset.

### Packet / cert engine
- **H6. Linux SLL2 (linktype 276) unsupported** (F4) -> silent zero-packet result
  on modern `tcpdump -i any`, the exact capture workflow we invite. Fix: handle 276.
- **H7. IPv4 fragmentation ignored** (F5); non-first fragments parsed as fresh L4
  headers, polluting the RTP flow table. Fix: skip fragment-offset > 0.
- **H8. SIP 487 (caller cancel) diagnosed as a domain-B config failure** (F6); 481/
  484/491 default to B too. Telling a vet a user hang-up is a transport problem.
  Fix: add a 487 "not a fault" cause; add 481/484.
- **H9. Cross-signed chain breaks `by_subject` dict** (F7). DigiCert G5 / Microsoft
  2017 cross-sign (the reality this tool exists for) collide; last cert wins ->
  false `CHAIN_INVALID` / `UNTRUSTED_ANCHOR`. Fix: `dict[str, list]`, try every
  subject-matching candidate whose signature verifies.

### Docs / drift (credibility hits an expert catches in seconds)
- **D1.** `PRODUCTION-PLAN.md` says "v0.14.0 ... 66 tests"; everything else says
  v0.15.0 / 79 tests. Also a duplicated `0.1 Key rotation` line.
- **D2.** `README.md` "Note on demo certificates" claims trust-anchor validation is
  NOT done, but `C.CERT.UNTRUSTED_ANCHOR`/`CHAIN_ANCHORED` are implemented and
  tested, and the same README says so 40 lines up. Self-contradiction on the
  flagship domain.
- **D3.** README intro says "runs A/B/C/D/E ... all five validators"; the body and
  code say 8 domains (A-G + S).
- **D4.** `knowledge-base/RECURSIVE_IMPROVEMENT.md` lists domain F (topology-leak)
  as missing; it shipped, is tested, and is advertised. Stale self-assessment.
- **D5.** `DOMAIN_REFERENCE.md` coverage table grades SRTP / topology / ACL as not
  done; all shipped.
- **D6.** `RUNBOOK.md` makes `docker pull ghcr.io/...:latest` the primary install,
  but no image was ever published (zero git tags). Partner fails at step one.
- **D7.** README + `demo.sh` header say "3-vendor fleet"; the demo runs 4 vendors.
- **E1.** 43 em dashes across README/PRODUCTION-PLAN/DOMAIN_REFERENCE/SYNC (house
  rule: zero in forward-facing writing); README also ends with two stray ``` fences.

---

## MEDIUM — correctness debt (selected)

- **M1.** DTMF severity inversion: the worse config scores lower (codec.py if/elif). (SV-08)
- **M2.** Codec matching is raw case-sensitive equality; "G.711"/"PCMU/8000" vs
  ruleset names -> false `E.CODEC.NO_TEAMS_OVERLAP`. Needs a canonicalizer. (SV-09, P-OR-3)
- **M3.** `S.ACL.IPV6_NEGLECT` fires HIGH on every v4-only deployment (the common
  case). Gate on evidence of v6 presence or downgrade. (SV-10)
- **M4.** HA diff omits `srtp_enabled` and cert expiry: an SRTP-off standby fails
  over to no media and reads clean. (SV-11)
- **M5.** Oracle `sip-port` / `tls-profile` flattening: first-port-wins reports the
  wrong transport; `mutual-authenticate disabled` invisible. (P-OR-1, P-OR-2)
- **M6.** Ribbon `transportProtocolsAllowed` comma list and `set ... pki certificate`
  counting the leaf as a root -> wrong transport / false root-present. (P-RB-1, P-RB-3)
- **M7.** Crash battery: truncated/malformed configs raise `IndexError`/`ValueError`
  across all parsers (no token-after guard, `getboolean` on bad values,
  `MissingSectionHeaderError`); one bad packet's Unicode digit crashes `analyze()`.
  `detect_and_parse` has no exception boundary; CLI validator/sim/score stages run
  outside the parser error boundary. (P-CR-1, F8, sec #4, sec #8)
- **M8.** UTC-vs-local date in cert expiry (F11); DER certs unsupported despite
  "PEM/DER" claim (F13); SDP folded/repeated/compact headers mis-parsed (F9);
  IPv4 total-length ignored so Ethernet padding leaks into payloads (F12).
- **M9.** HTTPS-only bypassable via HTTP redirect / SSRF; cache is user-writable and
  trusted as the freshness floor; `_write_result` path from config FQDN with weak
  sanitization; `serve --host 0.0.0.0` foot-gun. (sec #5, #6, #7, #9)

---

## Coverage gaps (test debt)

- 27 of 58 check IDs (47%) never asserted, including `C.CERT.EXPIRY`,
  `C.CERT.EKU_DUALUSE`, `B.SIP.OPTIONS_KEEPALIVE`, `C.TLS.MTLS_DISABLED`,
  `E.CODEC.NO_TEAMS_OVERLAP`. (T1)
- The trust-boundary headline (anon payload excludes FQDN/locator/CN/SAN) has zero
  tests; `report/anonymize.py` is never imported. (T2)
- HA drift: 7 of 9 checks untested. (T3)
- Verdict boundaries (HIGH->REVIEW, MEDIUM-only->PASS, 100-cap) thin. (T4)
- Per-validator "clean model -> zero findings" silence tests missing for B/D/E. (T5)
- Non-AudioCodes parsers happy-path only; no malformed/empty per vendor. (T6)
- `serve.py` and the simulate/explain/diff CLI handlers have no pytest. (T7)
- `acceptance.sh` is not wired into CI. (T7)

---

## What is genuinely solid (so the expert does not re-litigate it)

The signing/verify core (verify-before-cache ordering, non-overridable pinned key,
the rotated dev key does not match the pin), the `ruleset_id` charset gate, inbound
size caps, the loopback-only `serve` default, the server-rendered reports' full
`html.escape`, the minimal default-off double-gated anon payload, RFC 2818 wildcard
matching, the pcap endianness/magic handling, determinism throughout, and the G/S/
leaf-cert silence discipline. The problem is never that the discipline is wrong; it
is that it is applied unevenly.

## Fix order

1. Doc drift + editorial (D1-D7, E1): zero code risk, removes the cheapest
   embarrassments. **(this is the first commit)**
2. Tristate model + validator guards + parser honesty (C1, C2, H1): the core
   correctness theme; unifies "unknown vs absent".
3. simulate cert hard-stops (C3): small, high-impact.
4. Packet/cert engine correctness (C5, C6, H6, H7, H8, H9).
5. NAT realm role (C4), ACL per-version + shadowing (H2, H3), score gate (H4),
   cipher assertion (H5).
6. Security hardening (S1, S2, S3, M9).
7. Crash battery + coverage backfill (M7, M8, tests).

C7 (parser fidelity on real exports) stays the standing external ask.
