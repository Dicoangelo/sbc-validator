# SBC Validator: Review Packet (v0.16.0)

The independent, local-first, multi-vendor SBC validation tool. Runs inside the
customer's environment, air-gapped; raw configs never leave. This is a working
product, not a slide.

## See it in 60 seconds

```bash
sbc-validator demo                          # the whole flow, one command
sbc-validator serve --results results       # live dashboard at http://127.0.0.1:8787
sbc-validator report --results results --out fleet-report.html   # buyer leave-behind
```

`demo` validates a mixed fleet, predicts a call dying at the TLS handshake,
explains a rejected call from a packet capture, flags a security-exposed SBC, and
rolls up 2026 Microsoft CA-migration readiness.

## What's built and proven

- **8 commands:** validate, simulate (predict), explain (pcap post-mortem), diff
  (HA drift), fleet (readiness), serve (dashboard), demo, report.
- **4 real vendor parsers on one model:** AudioCodes (incl. the real Mediant
  table `.ini`), Cisco CUBE, Ribbon, Oracle Acme. Same validators run on all four.
- **8 validation domains:** A syntax/semantic, B interop, C TLS/CA wedge (SRTP +
  trust-anchor chain + wildcard-aware CN/SAN), D NAT, E codec (+ transcode/DSP),
  F topology-leak (pcap), G routing, **S security/access-control**.
- **Signed rule channel:** Ed25519-signed, authority-sourced (7 Microsoft roots
  from Microsoft Learn), HTTPS-only, rollback-floored; offline publisher key.
- **Productized:** 100 tests in CI (3 Python versions), air-gapped Docker image,
  clean-install acceptance harness (16/16), CI/CD gate, a one-tag-away release.

## What's deliberately NOT done (and why)

Honest gaps, all gated so they produce **zero false positives** until done right:

- **Routing (G) and security (S) for Cisco/Ribbon/Oracle.** Each vendor's
  grammar/semantics differ enough that modeling them blind would risk a *false
  verdict*, the one thing this tool can't afford. They stay silent for those
  vendors until we model a real config. (AudioCodes is real and firing.)
- **Per-config cipher-suite matching** (naming-convention risk), **live SIP/TLS
  probing**, **AI-assisted remediation** (intentionally engineer-applied, never
  auto-push). All Phase 2+.

## The one thing that unblocks the rest

A real SBC config per vendor. See **CONFIG-REQUEST.md** for exactly what to export
and how to sanitize it. Even one real config (any vendor) is high value, it's the
same path that made AudioCodes real.

## Where things live

- Code + everything: `Dicoangelo/sbc-validator` (private).
- Coverage matrix vs. the canonical failure modes: `VALIDATOR-COVERAGE.md`.
- Production plan + the three planes (engine / rule service / telemetry):
  `PRODUCTION-PLAN.md`.
- Operator runbook (how a partner runs it air-gapped): `RUNBOOK.md`.
