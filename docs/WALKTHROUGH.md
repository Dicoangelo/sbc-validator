# SBC Validator: End-to-End Walkthrough

One SBC, the whole way: a broken Teams Direct Routing config, parsed, validated
domain by domain, predicted to fail, then fixed and re-validated to green. Every
output below is real (`sbc-validator walk` / `validate`), not a mockup.

The two configs are in `samples/walkthrough/`:
`sbc-teams-01-broken.ini` (the before) and `sbc-teams-01-fixed.ini` (the after),
the same SBC.

## What you're actually uploading

The input is a **config export from the SBC**: the text file the box produces when
you dump its configuration. Nothing connects to the live SBC, it is a static file,
so the tool runs fully air-gapped and the raw config never leaves the environment.

| Vendor | The file | How to export it |
|---|---|---|
| AudioCodes Mediant | the `.ini` config | Web GUI: Setup → Administration → Maintenance → Configuration File → Save INI File (or the SBC Config Wizard output) |
| Cisco CUBE | `show running-config` output | run it on the box, save the text |
| Ribbon SBC Core | `show configuration` (the `set …` flat config) | same |
| Oracle Acme Packet | `show running-config` / `display-current-cfg` (ACLI) | same |

Optionally also a `.pcap` capture (for `explain`, the post-mortem) and a leaf-cert
`.pem` (which turns on the deep domain-C chain checks).

**Honest note on this walkthrough.** The `samples/walkthrough/*.ini` files used here
are **simplified, hand-authored** configs: clean teaching stand-ins, not a real
Mediant export. The tool also parses the **real** AudioCodes parameter-table `.ini`
(modeled against the Mediant manual, tested). For Cisco, Ribbon, and Oracle the
parsers read the real export shapes, but routing (G) and access-control (S) stay
deliberately silent until validated against a real config per vendor (see
CONFIG-REQUEST.md). One real export per vendor is the unlock.

## 0. Run it yourself (one command)

```bash
sbc-validator walk samples/walkthrough/sbc-teams-01-broken.ini
```

That prints the five stages below. Then run `validate` on the fixed file to watch
it turn green.

## 1. Ingest: raw vendor config to one model

The parser turns the AudioCodes `.ini` into a vendor-neutral `NormalizedConfig`.
Every check downstream reads this model, never the raw syntax, which is why the
same engine validates AudioCodes, Cisco, Ribbon, and Oracle.

```
  Teams leg:
      transport=tcp   mTLS=no   SRTP=no   keep-alive=no
      codecs=['PCMU', 'G722']   trusted roots in store: 5
  Media realm 'Default': advertised=10.50.30.40   symmetric-RTP=no
```

Already you can see the trouble: TCP not TLS, mTLS/SRTP off, only 5 roots, a
private media address.

## 2. Validate: each domain reasons over the model

`walk` runs all eight domains and shows which fire. On the broken SBC:

- **B (interop):** `B.SIP.TRANSPORT` (HIGH) transport is TCP, Teams needs TLS;
  `B.SIP.OPTIONS_KEEPALIVE` (MEDIUM) no health ping.
- **C (the 2026 wedge):** `C.CA.ROOT_MISSING` (CRITICAL) 2 of 7 roots missing, the
  DigiCert TLS G5 pair Microsoft is migrating onto; `C.TLS.MTLS_DISABLED` (HIGH);
  `C.SRTP.DISABLED` (HIGH) no encrypted media.
- **D (NAT / media):** `D.NAT.PRIVATE_ADVERTISED` (CRITICAL) a private IP in SDP,
  remote media can't return; `D.NAT.NO_SYMMETRIC_RTP` (MEDIUM).
- **A, E, G, S:** clean or silent (the config carries nothing for them to judge,
  so they stay quiet rather than guess, the "silence beats a wrong verdict" rule).

Each finding prints its `why` and a concrete `fix`.

## 3. Verdict

```
  Risk score: 100/100      VERDICT: BLOCK
  Findings: CRITICAL 2, HIGH 3, MEDIUM 2
```

Severity-weighted, and any CRITICAL forces BLOCK. This SBC must not ship.

## 4. Predict the call

The simulator models a real call as a chain (TLS handshake, SIP, SDP, media) and
shows how far it gets:

```
  Outcome: NO_CONNECT   (dies at: TLS handshake)

  SBC     Microsoft Teams SIP proxy
          -------------------------
            --> TLS ClientHello
            <-- TLS alert: unknown CA / handshake failed   << call dies here
```

The missing roots mean the handshake never completes: no call connects, in either
direction. This is the "scream test" the product exists to prevent, caught from
config before the outage.

## 5. Fix it, then prove it

`sbc-teams-01-fixed.ini` is the same SBC with each finding remediated:

| Finding | Fix in the config |
|---|---|
| `C.CA.ROOT_MISSING` | add the DigiCert TLS ECC/RSA G5 roots to the trust store |
| `C.TLS.MTLS_DISABLED` | `mtls = true` on the Teams TLS context |
| `C.SRTP.DISABLED` | `srtp = true` on the Teams leg |
| `B.SIP.TRANSPORT` | `transport = tls` |
| `B.SIP.OPTIONS_KEEPALIVE` | `options_keepalive = true` |
| `D.NAT.PRIVATE_ADVERTISED` | advertise a public, routable media IP |
| `D.NAT.NO_SYMMETRIC_RTP` | `symmetric_rtp = true` |

Re-validate:

```bash
sbc-validator validate samples/walkthrough/sbc-teams-01-fixed.ini \
  --ruleset rulesets/ms_direct_routing_2026-06.json
```

```
  Verdict: PASS   Risk score: 0/100
  No findings.
  Predicted call: STABLE — call connects with two-way audio using PCMU.
```

The same SBC now passes, and the predicted call connects end to end:

```
  SBC     Microsoft Teams SIP proxy
            --> TLS ClientHello
            <-- TLS handshake OK
            --> OPTIONS (keep-alive)        <-- 200 OK
            --> INVITE  SDP offer: PCMU,G722
            <-- 180 Ringing   <-- 200 OK  SDP answer: PCMU
            --> ACK
           ===  RTP PCMU bidirectional  ===
```

## What this demonstrates

- **One model, every vendor.** The walk reads `NormalizedConfig`; the same flow runs
  on a Cisco, Ribbon, or Oracle export.
- **Deterministic, explainable verdicts.** Every finding has a why and a fix; no LLM
  guesswork in the verdict path.
- **Predict and confirm.** `simulate` predicts the failure from config; fixing the
  config flips the prediction to a clean two-way call.
- **Closed loop.** Broken to diagnosed to fixed to green, reproducible on demand.
