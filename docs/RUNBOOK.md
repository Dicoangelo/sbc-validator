# SBC Validator: Operator Runbook

Run the validator inside your own environment. Raw SBC configs never leave the
host. This is a pre-GA pilot build; see "Pre-GA notes" at the end.

## What it does

Validates Session Border Controller configs (AudioCodes, Cisco CUBE, Ribbon,
Oracle Acme) against the current Microsoft Direct Routing requirements, predicts
how a call would fail, and explains a packet capture in plain English. It gives
each SBC a risk score and a PASS / REVIEW / BLOCK verdict, and it never pushes
changes to your SBCs. It only reads.

## The air-gapped guarantee

`validate`, `simulate`, `explain`, `diff`, and `fleet` need no network. Run the
container with `--network none` and the raw config physically cannot leave the
host. This is the point of the local-first design and you can prove it yourself
with the flag below.

## Prerequisites

- Docker (or Python 3.10+ if you prefer to run it without a container).
- A directory of SBC config exports (`.ini`, IOS-XE running-config, Ribbon
  set-config, or Oracle ACLI).
- A signed rule bundle (shipped with the pilot, e.g. `ms_direct_routing_2026-06.json`).

## Install

Container (recommended), pull the pilot image:

```bash
docker pull ghcr.io/dicoangelo/sbc-validator:latest
```

Or run from source without a container:

```bash
pip install .            # from the repo
sbc-validator --help
```

## See everything in one command

```bash
docker run --rm --network none ghcr.io/dicoangelo/sbc-validator:latest demo
```

Runs the full four-vendor showcase: validates a mixed fleet, predicts a call
that dies at the TLS handshake, explains a rejected call from a capture, and
rolls up 2026 CA-migration readiness. Good for a first look before pointing it
at your own configs.

## Validate one SBC (air-gapped)

The signed ruleset ships in the image, so `--ruleset` is optional:

```bash
docker run --rm --network none -v "$PWD/configs:/work" \
  ghcr.io/dicoangelo/sbc-validator:latest validate /work/teams.ini
```

Exit code is 0 for PASS, non-zero for BLOCK (tune with `--fail-on review`), so it
gates a pipeline. Add `--html /work/report.html` for a customer-facing report.

## Fleet readiness (are we ready for the 2026 CA migration?)

```bash
docker run --rm --network none -v "$PWD/configs:/work" \
  ghcr.io/dicoangelo/sbc-validator:latest \
  fleet /work --ruleset rulesets/ms_direct_routing_2026-06.json
```

Prints "X of N SBCs ready" and exits non-zero if any carry a TLS/CA/cert/SRTP
blocker.

## Live dashboard

Write each run to a results directory, then serve the dashboard locally:

```bash
# 1) validate configs with --out so each run is recorded
docker run --rm --network none -v "$PWD:/work" -w /work \
  ghcr.io/dicoangelo/sbc-validator:latest \
  validate /work/configs/teams.ini --ruleset rulesets/ms_direct_routing_2026-06.json \
  --out /work/results --site HQ

# 2) serve the dashboard (loopback-published; rebuilds live as new runs land)
docker run --rm -p 8787:8787 -v "$PWD/results:/app/results" \
  ghcr.io/dicoangelo/sbc-validator:latest \
  serve --results /app/results --host 0.0.0.0
# open http://127.0.0.1:8787
```

The dashboard is local only. It is never hosted off your environment.

## Executive leave-behind (one forwardable file)

```bash
sbc-validator report --results results --out fleet-report.html
```

A single self-contained HTML page (no server): 2026 CA-migration readiness,
deploy verdicts, security-posture (access-control) exposure count, and the most
common findings across the fleet. The artifact you forward after a walkthrough.

## Predict and explain

```bash
# predict how far a call gets, from config alone (offline)
sbc-validator simulate configs/teams.ini --ruleset rulesets/ms_direct_routing_2026-06.json

# post-mortem a packet capture (no Wireshark needed)
sbc-validator explain capture.pcap
```

## Where rules come from

Rule bundles are Ed25519-signed and verified against a pinned publisher key
before use. They are distributed separately from the code so a CA change does
not require a new release. A stale or tampered bundle is refused. You always run
against a bundle whose version is stamped into every report.

## Pre-GA notes

- The publisher signing key is an offline software key during the pilot; it
  moves to an HSM before GA.
- The AudioCodes parser is validated against the Mediant manual and public
  config notes. A raw export from your environment will harden it further; share
  one if you can.
- This build is for design-partner evaluation, not production SLAs yet.

Contact: Dico Angelo (dicoangelo@metaventionsai.com) and Philip Drammeh.
