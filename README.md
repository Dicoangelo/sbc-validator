# SBC-AutoOps — Local-First SBC Validator

Vendor-agnostic, **local-first** pre-deployment validator for Session Border
Controllers. Parses an exported config inside the customer trust boundary, runs
A/B/C/D/E checks, and produces an explainable report + risk score + deploy
verdict. **Raw configs never leave.** Only rule sets come in; only opt-in
anonymized findings can go out.

It implements all five validators end-to-end (A syntax/semantic, B interop,
C TLS/CA — the Microsoft Direct Routing wedge, D NAT / one-way audio, E codec)
and ships **three real vendor parsers — AudioCodes, Cisco CUBE (IOS-XE), and
Ribbon SBC Core** — running on a single normalized model, plus an honest stub
for Oracle/Acme. Three vendors on one model is the proof that validation is
genuinely vendor-agnostic: the same C validator catches the 2026 root-CA gap on
an AudioCodes `.ini` and a Cisco running-config, and the clientAuth-only EKU
deprecation on a Ribbon `set`-config, all unmodified.

It also detects **HA configuration drift** between an Active and a Standby node
(`diff` subcommand): the trust-store-drift case is rated CRITICAL because a
failover during the 2026 CA rotation onto a drifted standby hard-stops calls.

## Quickstart

```bash
# one command runs the whole 3-vendor fleet demo + HA drift check:
./demo.sh

# a single config (any of the three vendors auto-detected):
python -m sbc_validator.cli validate samples/ribbon_sbc.cli \
    --ruleset rulesets/ms_direct_routing_2026-06.json \
    --html report.html          # self-contained customer report

# HA drift: compare an active node against its standby
python -m sbc_validator.cli diff samples/clean_pass.ini samples/audiocodes_standby.ini
```

Add `--json` for machine output. Opt-in anonymized telemetry (off by default,
double-gated):

```bash
python -m sbc_validator.cli validate samples/audiocodes_min.ini \
    --ruleset rulesets/ms_direct_routing_2026-06.json \
    --share-anon --consent --org-salt <your-salt>
```

## Trust-boundary guarantees (enforced in code)

- Parsing + validation are pure-local; no network calls in the data path.
- The rule client is the only inbound channel. Bundles are **versioned + signed**
  and verified before use; the verified version is stamped into every report
  ("freshness assertion"). A stale/tampered bundle can't silently pass you.
- Anonymized export requires **both** `--share-anon` and `--consent`. The payload
  contains only `check_id`, `severity`, vendor family, ruleset version, and a
  salted org token — never locators, FQDNs, CN/SAN, IPs, or free text.

## Repo layout

```
sbc_validator/
  models.py              normalized vendor-neutral config model
  cli.py                 entrypoint: parse -> validate -> report
  rules/client.py        signed, versioned rule-bundle client (offline-capable)
  parsers/
    base.py              parser contract
    audiocodes.py        AudioCodes parser (complete) + Cisco/Ribbon/Oracle stubs
  validators/
    base.py              Finding / Severity / AbstractValidator
    ca_compliance.py     C — Microsoft DR TLS/CA wedge
    nat_traversal.py     D — NAT / one-way audio
  report/
    risk.py              severity-weighted score + deploy verdict
    anonymize.py         opt-in, minimal, non-reversible payload
rulesets/                signed rule bundles
samples/                 sample config (intentional misconfigs) for smoke test
```

## Microsoft Direct Routing 2026 facts encoded (sourced + verified 2026-06-07)

Every rule is sourced and cited in **[RULE_AUTHORITY.md](RULE_AUTHORITY.md)**.

- Trust store must contain **all 7 required Microsoft/DigiCert root CAs**, each
  with its SHA-1 thumbprint, in the signed ruleset. This now includes the new
  **DigiCert TLS ECC P384 Root G5** and **DigiCert TLS RSA 4096 Root G5** that
  Microsoft is migrating onto (the earlier placeholder list wrongly carried the
  retired Baltimore root and a bogus 2018 root, and missed the G5 pair).
- Root matching is **naming-tolerant**: `DigiCert Global Root G2`,
  `DigiCertGlobalRootG2`, and the SHA-1 thumbprint all match.
- SBC leaf cert must include the **Server Authentication EKU** (enforced June
  2026); clientAuth-only / dual-use server certs are deprecated → warned.
- **TLS 1.2**; SIP cipher allowlist and SRTP `AES_CM_128_HMAC_SHA1_80` are carried
  in the ruleset (active cipher/TLS-version validation is roadmap).
- Timeline: trust-store remediation by end of Feb 2026, server-side cert rotation
  from April 2026, serverAuth-EKU enforcement June 2026. Failure mode is a hard
  TLS handshake stop (the "scream test" this prevents). Microsoft test endpoint:
  `sip.g1.pstnhub.microsoft.com:5061`.

> **Before production:** re-verify the root list against Microsoft's live Azure
> Certificate Authority details page and re-sign the bundle (see RULE_AUTHORITY.md).
> The values here are sourced and dated, not frozen; CA lists change.

## What's deliberately NOT done yet (roadmap)

- Oracle/Acme parser — stub raises `NotImplementedError` (needs a real sample
  export). **AudioCodes, Cisco CUBE, and Ribbon are implemented** (see below).
- Trust-anchor chain *validation* against a configured root store (current deep
  pass builds the chain and checks it isn't broken, but doesn't verify the anchor).
- Remote rule-fetch transport (resolution + cache + verify is in place; the HTTP
  call is the TODO).
- Docker image / CI pipeline wiring.
- Everything in Phase 3/4 (agentic reasoning, live probing, SaaS).

## Now implemented

- **A/B/C/D/E** validators all live and (B/C/D/E) ruleset-driven:
  A = syntax/semantic baseline, B = interop, C = TLS/CA wedge (incl. an **SRTP**
  media-encryption check), D = NAT, E = codec.
- **Three real vendor parsers on one normalized model: AudioCodes (`.ini`),
  Cisco CUBE (IOS-XE running-config), and Ribbon SBC Core (`set`-config).** The
  same validators run unmodified across all three — the vendor-agnostic claim,
  demonstrated. Cisco BLOCKs on a missing 2026 root CA; Ribbon REVIEWs on a
  clientAuth-only leaf (the EKU deprecation).
- **HA drift detection** (`diff <active> <standby>`): compares the failover-critical
  fields between two node configs and rates trust-store drift CRITICAL.
- **Predicted call-flow simulation** (`simulate <config>`): models a real call as
  a chain (TLS handshake -> SIP signaling -> SDP offer/answer -> media path),
  predicts how far it gets, names the user-visible symptom, and renders the SIP
  ladder up to the failure. Deterministic and offline (originates no traffic).
  Every `validate` report (text + HTML) also carries the predicted outcome.
- **PCAP explainer** (`explain <capture.pcap>`): the post-mortem twin of
  `simulate`. A pure-stdlib classic-pcap reader (no Wireshark/tshark/scapy)
  reconstructs the SIP ladder from a real capture, detects RTP flow direction
  (one-way audio), and explains why a call failed (488 codec, private media IP,
  unanswered OPTIONS, TLS alert), mapping each cause back to a validator domain
  (B/C/D/E) and the config fix. Also detects **topology leaks** (domain F): private/
  internal IPs exposed in Contact/Via/Record-Route/P-Asserted-Identity headers, the
  signaling-plane counterpart to B2BUA topology hiding. Scope: SIP-over-UDP + RTP,
  with a best-effort note for TLS-encrypted SIP. Sample captures + generator in `samples/`.
- **Real certificate inspection** (`cert_inspect.py`, via `cryptography`):
  EKU, SAN, expiry, issuer, local chain-build; C runs it on any referenced cert.
- **Ed25519 bundle signing** with a pinned publisher public key; tampered
  bundles are rejected before use. Sign/re-sign via
  `python -m sbc_validator.tools.sign_ruleset <bundle> <key.pem>`.
- **Customer-facing HTML report** (`--html <path>`): self-contained, no JS/network,
  severity chips + verdict banner + per-finding why/fix. Internal artifact only.
- **Turnkey demo** (`./demo.sh`): validates the 3-vendor fleet, writes an HTML
  report per SBC, builds `dashboard_data.json`, runs an HA-drift check, and prints
  the verdict table.
- **Installable package** (`pip install -e .`) exposing the `sbc-validator`
  console command.
- **Test suite** (`pytest`, 39 tests) covering all three parsers, the five validators,
  SRTP, HA drift, call-flow simulation, the pcap explainer (incl. topology leak),
  signing verify/tamper, cert inspection, risk scoring, and HTML rendering.

## Note on demo certificates

The sample leaf PEMs (`samples/*_leaf.pem`) are self-signed fixtures that exist to
exercise EKU/SAN/expiry inspection. A production SBC presents a CA-issued leaf;
trust-anchor validation against a configured root store is the next deepening of
domain C (the current pass confirms the chain isn't broken, not that it terminates
at a trusted anchor).

## Security note (skeleton)

`dev/dev_signing_key.pem` and the pinned public key in `rules/client.py` are
**development** keys. In production, generate a real publisher keypair, keep the
private key offline / in an HSM, and replace `_PINNED_PUBLIC_KEY_B64`.
```
```
