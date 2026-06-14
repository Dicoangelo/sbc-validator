<img src="https://capsule-render.vercel.app/api?type=waving&height=300&color=0:1a0a12,50:6e1340,100:9d1b54&text=SBC-AutoOps&fontSize=66&fontColor=ffffff&animation=fadeIn&fontAlignY=35&desc=The%20independent%20pre-deployment%20truth%20layer%20for%20real-time%20voice&descSize=17&descAlignY=56&descAlign=50" width="100%" alt="SBC-AutoOps"/>

<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=600&size=21&duration=3200&pause=1000&color=9D1B54&center=true&vCenter=true&multiline=false&repeat=true&width=760&height=40&lines=5+Vendor+Parsers+%E2%80%A2+8+Validation+Domains+%E2%80%A2+Deterministic+Verdicts+%E2%80%A2+Air-Gapped" alt="Typing SVG" />

<br/>

[![Built by Dico Angelo](https://img.shields.io/badge/Built_by-Dico_Angelo-9d1b54?style=for-the-badge&logo=github&logoColor=white&labelColor=2b0a18)](https://github.com/Dicoangelo)
<img src="https://img.shields.io/badge/Telecom-Philip_Drammeh-6e1340?style=for-the-badge&labelColor=2b0a18" alt="Telecom architecture by Philip Drammeh" />
[![Live demo](https://img.shields.io/badge/Live-Business_Case-9d1b54?style=for-the-badge&labelColor=2b0a18)](https://sbcvalidator.metaventionsai.com)
[![Free scanner](https://img.shields.io/badge/Free-Readiness_Scanner-9d1b54?style=for-the-badge&labelColor=2b0a18)](https://sbcvalidator.metaventionsai.com/scanner)
[![License](https://img.shields.io/badge/License-Proprietary-6e1340?style=for-the-badge&labelColor=2b0a18)](#license)

<br/>

<img src="https://img.shields.io/badge/Tests-182-9d1b54?style=for-the-badge&labelColor=2b0a18" alt="Tests" />
<img src="https://img.shields.io/badge/Vendors-5-9d1b54?style=for-the-badge&labelColor=2b0a18" alt="Vendors" />
<img src="https://img.shields.io/badge/Domains-8-9d1b54?style=for-the-badge&labelColor=2b0a18" alt="Domains" />
<img src="https://img.shields.io/badge/Checks-59-9d1b54?style=for-the-badge&labelColor=2b0a18" alt="Checks" />
<img src="https://img.shields.io/badge/Verdicts-PASS%2FREVIEW%2FBLOCK-9d1b54?style=for-the-badge&labelColor=2b0a18" alt="Verdicts" />

<br/><br/>

<img src="https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white&labelColor=2b0a18" alt="Python" />
<img src="https://img.shields.io/badge/Docker-Air--gapped-2496ED?style=for-the-badge&logo=docker&logoColor=white&labelColor=2b0a18" alt="Docker" />
<img src="https://img.shields.io/badge/Rulesets-Ed25519_signed-9945FF?style=for-the-badge&logoColor=white&labelColor=2b0a18" alt="Ed25519" />
<img src="https://img.shields.io/badge/Stdlib-only_engine-1e7e34?style=for-the-badge&labelColor=2b0a18" alt="Stdlib" />

<br/>

*Reads any SBC vendor's config before deploy and tells you, in plain English, exactly what will break. Local-first and air-gapped: raw configs never leave your environment.*

</div>

<br/>

> **Every business call crosses a Session Border Controller** — the fragile, multi-vendor gateway between your network and the carrier. One misconfiguration and calls fail silently: one-way audio, dead trunks, hours of repair, and you hear about it from users, not a dashboard. SBC-AutoOps is the independent layer that catches the break in the **config**, before you ship it.

<br/>

## Architecture

<div align="center">
<img src="marketing/diagrams/sbc-autoops-architecture-web.webp" width="92%" alt="SBC-AutoOps architecture: five vendor configs normalized into one model, validated across eight domains in three modes, producing a PASS / REVIEW / BLOCK verdict, air-gapped, signed rules in and anonymized findings out."/>
</div>

```mermaid
flowchart LR
  subgraph IN["Vendor SBC configs"]
    A["AudioCodes"]; C["Cisco CUBE"]; R["Ribbon"]; O["Oracle Acme"]; M["Metaswitch Perimeta"]
  end
  IN --> P["Parsers"] --> N["Normalized model"] --> V["Validators · 8 domains"] --> MD["Modes"] --> VD{"Verdict"}
  VD --> PASS(["PASS"]); VD --> REVIEW(["REVIEW"]); VD --> BLOCK(["BLOCK"])
  RB["Signed rule bundle"] -. inbound .-> V
  V -. opt-in .-> AF["Anonymized findings"]

  classDef garnet fill:#9d1b54,stroke:#2b0a18,color:#fff;
  classDef wine fill:#2b0a18,stroke:#9d1b54,color:#fff;
  class P,N,V,MD garnet;
  class A,C,R,O,M,RB,AF wine;
```

<div align="center">

```
   VALIDATE              →            PREDICT             →           EXPLAIN
   read the config                    model the call                 diagnose a capture
   across 8 domains                   TLS → SIP → SDP → media         reconstruct the SIP ladder

   ════════════════════════════════════════════════════════════════════════════════════════

   • Deterministic verdicts, not LLM guesses        • Air-gapped, local-first execution
   • Microsoft-authoritative 2026 CA / EKU rules    • Ed25519-signed rulesets, rollback refusal
   • Refuses to guess: silent where it cannot prove • Five vendors, one normalized model
```

</div>

<br/>

## Five vendors, one model

| Vendor | Format | Depth |
|---|---|---|
| **AudioCodes** | `.ini` (table + simple) | Full: TLS, cert, SRTP, codec, NAT, routing, security |
| **Cisco CUBE** | IOS-XE | TLS, cert, SRTP, codec, NAT (routing/security roadmap) |
| **Ribbon** | SBC Core `set-config` | TLS, cert, SRTP, codec, NAT (routing/security roadmap) |
| **Oracle Acme** | Acme Packet ACLI | TLS, cert, SRTP, codec, NAT (routing/security roadmap) |
| **Metaswitch Perimeta** | adjacency CLI | Interop / transport posture. Trust store, cert and codec live outside the export, so those domains stay silent and are verified out of band. |

*The engine refuses to guess. Where a config format cannot prove a fact, the verdict says "verify out-of-band" rather than inventing one.*

## Eight validation domains

| | Domain | Catches |
|---|---|---|
| **A** | Syntax / semantic | Malformed config, dangling references |
| **B** | Interop | TLS transport, OPTIONS keep-alive, header normalization |
| **C** | TLS / CA — *the 2026 wedge* | Missing Microsoft roots, mTLS off, SRTP off, EKU, chain validity |
| **D** | NAT / media | Private IP in SDP, missing symmetric RTP → one-way audio |
| **E** | Codec | Cross-leg overlap, forced transcode, DTMF |
| **F** | Topology leak | Private-IP leakage on the signaling plane |
| **G** | Routing / classification | 404 / unclassified Teams routing |
| **S** | Security | ACL default-deny, broad CIDR, shadowing |

## Quick start

```bash
# one packaged command runs the whole demo-fleet showcase
sbc-validator demo

# validate a single config (any of the five vendors auto-detected)
sbc-validator validate sbc-configs/teams.ini \
    --ruleset rulesets/ms_direct_routing_2026-06.json \
    --html report.html

# predict the call, diagnose a capture, diff an HA pair, roll up a fleet
sbc-validator simulate sbc-configs/teams.ini
sbc-validator explain capture.pcap
sbc-validator diff active.ini standby.ini --fail-on review
sbc-validator fleet sbc-configs/

# map findings to a regulatory control framework
sbc-validator report --compliance mifid2 --results results/

# outside-in: live TLS handshake to an SBC edge, graded vs the ruleset
sbc-validator probe sbc.contoso.com

# the local console: fleet view, findings, reports, bundle provenance
# (reads results/, never leaves the box)
sbc-validator serve
```

`validate` returns a non-zero exit code, so it drops straight into CI and fails the build before a non-compliant config reaches the change window.

## See it

<div align="center">
<img src="marketing/diagrams/dashboard-demo.webp" width="92%" alt="SBC-AutoOps fleet dashboard: seven SBCs across five vendors with deploy verdicts, findings-by-domain and severity-trend charts, average risk per vendor, a verdict donut, and a severity-by-domain heatmap."/>
</div>

- **[Live business case](https://sbcvalidator.metaventionsai.com)** — the product, the 2026 deadline, the market
- **[Security & data handling](https://sbcvalidator.metaventionsai.com/#security)** — the data-flow contract, stated precisely
- **[Live dashboard demo](https://sbcvalidator.metaventionsai.com/dashboard/)** — the fleet view, sample data
- **[Setup Guide](https://sbcvalidator.metaventionsai.com/dashboard/#setup)** — the four run paths, copy-paste ready
- **[Free readiness scanner](https://sbcvalidator.metaventionsai.com/scanner)** — outside-in TLS grade for any SBC FQDN; edge-only, unauthenticated, stores nothing (grades + check IDs aggregate only, never hostnames)
- **[State-of-readiness benchmark](https://sbc-autoops-scanner.fly.dev/stats)** — anonymized aggregate grades

## Security & data handling

The data-flow contract is documented precisely in **[docs/SECURITY.md](docs/SECURITY.md)**,
written to be lifted into a security review. The short version:

- **Inbound, one channel:** a versioned, Ed25519-signed rule bundle, verified before use
  against a publisher key pinned in source (`sbc_validator/rules/client.py`), with a
  compiled-in freshness floor that refuses rollback. Configs never travel this channel.
- **Outbound, default:** nothing. No telemetry, no call-home. `docker run --network none`
  is the documented production mode.
- **Outbound, opt-in (`--share-anon`):** check IDs, severities, vendor family, ruleset
  version, salted org token. Never config text, FQDNs, CN/SAN, IPs, or file paths
  (`sbc_validator/report/anonymize.py`).
- **Verify, don't trust:** build from source on your side. `sha256sum -c SHA256SUMS`
  verifies the tree (regenerate with `scripts/integrity-manifest.sh`); a runtime
  CycloneDX SBOM ships at `docs/sbom-cyclonedx.json`. One runtime dependency
  (`cryptography`). Docker is packaging, not a requirement: plain `pip install .` on
  any Python 3.10+ host, fully-offline wheel installs, and rootless Podman all work.

## What's verified, stated up front

Capabilities described as available are implemented and tested (**182 tests in CI**, three Python versions). Routing and security depth for Cisco, Ribbon, and Oracle, per-config cipher matching, and live probing stay **silent** until validated against a real config for that vendor. Metaswitch Perimeta is read from an adjacency-CLI export that does not carry the trust store, certificate, or codec policy inline, so those domains stay silent for it. The tool refuses to guess — a wrong verdict is the one thing a pre-deployment control cannot afford.

## Project layout

```
sbc_validator/
  models.py              normalized vendor-neutral config model
  cli.py                 entrypoint: validate/simulate/explain/diff/fleet/serve/report/probe/demo
  parsers/               audiocodes, cisco_cube, ribbon, oracle, perimeta (Metaswitch)
  validators/            A syntax, B interop, C ca/tls, D nat, E codec, ha_drift, G routing, S security
  report/                risk, html (per-SBC), exec (fleet), compliance (control frameworks), anonymize
  rules/client.py        signed, versioned, rollback-floored rule-bundle client
  call_sim.py            deterministic call-flow prediction (TLS → SIP → SDP → media)
  web/                   the packaged dashboard + scanner front-ends
marketing/               the business case, architecture diagrams, hosted demo dashboard
rulesets/                Microsoft-authoritative 2026 Direct Routing rule bundle (Ed25519-signed)
```

<br/>

## License

Proprietary — © 2026, all rights reserved. Not licensed for redistribution. A commercial product in active development; partnership and design-partner inquiries welcome.

<br/>

<div align="center">

**Built by [Dico Angelo](https://github.com/Dicoangelo)** — AI builder and systems architect.
**Telecom architecture by Philip Drammeh** — ex-Microsoft Teams Direct Routing specialist.

*Telecom domain depth meets AI build velocity.*

</div>

<img src="https://capsule-render.vercel.app/api?type=waving&height=120&color=0:9d1b54,50:6e1340,100:1a0a12&section=footer" width="100%"/>
