# Rule Authority

The validator is only as trustworthy as its rules. A confident PASS on a wrong
rule set is worse than no tool: it manufactures false confidence and the outage
happens anyway. This document is the chain of custody for every rule in
`rulesets/ms_direct_routing_2026-06.json`: where it came from, when it was
verified, and how to keep it current without silent drift.

## Sources (authoritative)

| Rule area | Source | Last verified |
|---|---|---|
| Required root CAs (7) + SHA-1 thumbprints | Microsoft Learn, *Direct Routing What's New*, "Update on upcoming certificate changes (2025-12-12)" | 2026-06-07 |
| serverAuth EKU REQUIRED on SBC leaf (always). PRECISION: MS SIP interface still ACCEPTS SBC certs WITHOUT clientAuth EKU "for the foreseeable future"; the June-2026 change is that public CAs stop issuing clientAuth in server certs (Chrome Root Program v1.6), so certs become serverAuth-only. MS may require clientAuth on SBC certs in the future (not yet). | *Direct Routing What's New*, "Clarification on Client Authentication EKU" + "Update (2025-12-12)" | 2026-06-09 |
| TLS 1.2 (forced) + the four SIP cipher suites; SRTP `AES_CM_128_HMAC_SHA1_80` | Microsoft Learn, *[Connect your SBC to Direct Routing](https://learn.microsoft.com/en-us/microsoftteams/direct-routing-connect-the-sbc)* — "Microsoft forces TLS1.2... one of the following cipher suites: ...256_GCM_SHA384, ...128_GCM_SHA256, ...256_CBC_SHA384, ...128_CBC_SHA256". EXACT match to ruleset verified 2026-06-09. SRTP suite from *What's New* SDP example. | 2026-06-09 |
| Test endpoint `sip.g1.pstnhub.microsoft.com:5061`; end-March SBC-side / April-2026 server-side rotation | Microsoft Learn, *Direct Routing What's New*, "Testing endpoint (2026-02-16)" | 2026-06-09 |
| Teams-supported codecs (SILK, G.711, G.722, G.729, AMR-WB newly enabled) | *Direct Routing plan* (codecs) + *What's New* (AMR-WB) | 2026-06-09 |
| SIP OPTIONS interval: 60-180s per trunk/endpoint; in-band DTMF NOT supported; SDES-SRTP required | *Connect the SBC* + *Direct Routing protocols (RFC standards)* | 2026-06-09 |

URLs:
- https://learn.microsoft.com/en-us/microsoftteams/direct-routing-whats-new
- https://learn.microsoft.com/en-us/azure/communication-services/concepts/telephony/direct-routing-infrastructure
- Live root list (always re-check before a pilot): Azure Certificate Authority details page, and the Microsoft-included CA list at the CCADB.

## The 7 required root CAs (verified 2026-06-07)

| CA | SHA-1 thumbprint |
|---|---|
| DigiCert Global Root CA | A8985D3A65E5E5C4B2D7D66D40C6DD2FB19C5436 |
| DigiCert Global Root G2 | DF3C24F9BFD666761B268073FE06D1CC8D4F82A4 |
| DigiCert Global Root G3 | 7E04DE896A3E666D00E687D33FFAD93BE83D349E |
| DigiCert TLS ECC P384 Root G5 | 17F3DE5E9F0F19E98EF61F32266E20C407AE30EE |
| DigiCert TLS RSA 4096 Root G5 | A78849DC5D7C758C8CDE399856B3AAD0B2A57135 |
| Microsoft ECC Root Certificate Authority 2017 | 999A64C37FF47D9FAB95F14769891460EEC4C3C5 |
| Microsoft RSA Root Certificate Authority 2017 | 73A5E64A3BFF8316FF0EDCCC618A906E4EAE4D74 |

### What was wrong before (and why this matters)

The pre-2026-06-07 ruleset was operator-placeholder and wrong in the way that
breaks customers: it listed **BaltimoreCyberTrustRoot** (the *retired* root) and
**MicrosoftRSARootCA2018** (not a real Teams DR root), and it was **missing the
two new DigiCert G5 roots** Microsoft is migrating onto. A customer running it
would have been told to fix the wrong things while the validator stayed silent on
the actual 2026 gap. The test suite now guards against any wrong-but-still-7 list
(`test_signed_ruleset_verifies` asserts the G5 pair is present and Baltimore/2018
are absent).

## Matching is naming-tolerant by design

Real trust stores label the same CA inconsistently. The C validator normalizes
identifiers (lowercase, strip non-alphanumerics, fold "Certificate Authority" to
"CA") and also accepts a SHA-1 thumbprint match. So `DigiCert Global Root G2`,
`DigiCertGlobalRootG2`, and the thumbprint all resolve to the same root. See
`_norm()` in `sbc_validator/validators/ca_compliance.py`.

## Re-sign workflow (when a rule changes)

1. Edit `rulesets/ms_direct_routing_2026-06.json`. Bump `bundle_version` and
   `verified_on`. Update `sources` if needed.
2. Re-sign with the offline publisher key (kept outside the repo):
   ```bash
   python -m sbc_validator.tools.sign_ruleset \
       rulesets/ms_direct_routing_2026-06.json ~/.sbc-validator/keys/publisher_ed25519.pem
   ```
   The private key never lives in git. If you rotate the publisher key, also
   update `_PINNED_PUBLIC_KEY_B64` in `rules/client.py` to the new public half.
   (Migrate the private key to an HSM before GA.)
3. Run `pytest`. The authority guard test will fail if the root set regressed.
4. Run `./demo.sh` and confirm the fleet verdicts still make sense.
5. Commit with a message naming the source and date of the change.

## Review cadence

- **Before every pilot / customer engagement:** re-verify the root list against
  the live Azure CA details page. CA lists change; a stale list is the failure
  mode this whole document exists to prevent.
- **Quarterly** at minimum, and **immediately** on any Microsoft Direct Routing
  certificate announcement.

## Still pending operator confirmation before production

The thumbprints and counts above are sourced and cited, but you (the operator)
own the final pre-pilot verification against Microsoft's live page. Treat this
file as "sourced and dated," not "frozen truth."
