# SBC Validator: Operator Runsheet

The one page to drive the product without thinking about Python. Full
functionality, one-command access.

## Where everything lives (the map)

There is ONE source of truth, and everything else derives from it.

| Thing | Location | Note |
|---|---|---|
| **The product (code, docs, rules)** | `~/projects/sbc-validator` | the repo, single source of truth |
| Global launcher | `~/bin/sbc-validator` | runs the full CLI from any terminal |
| Double-click dashboard | `~/Desktop/SBC Validator.command` | opens the dashboard, no terminal |
| Review packet (handoff) | `~/Desktop/SBC Philip Review/` | DERIVED: rebuild with one command (below) |
| Old snapshots | `~/Desktop/SBC ARCHIVE (...)/` | frozen history, do not use |

You never edit the Desktop folders by hand. The launchers and the packet are
generated from the repo.

## Open the dashboard (zero setup)

Either one:

- **Double-click** `SBC Validator.command` on the Desktop. It refreshes the fleet
  and opens the dashboard in your browser. Close the window to stop.
- Or from any terminal: `sbc-validator-dashboard` (same thing).

The dashboard shows the 6-SBC fleet, verdicts (BLOCK / REVIEW / PASS), 2026 CA
readiness, the domain heatmap, and per-SBC findings. It is read-only and local; no
config ever leaves the machine.

## Drive it from the terminal (full CLI, from anywhere)

`sbc-validator <command>` works from any directory (the `~/bin` launcher handles
the environment). The eight commands:

```bash
sbc-validator demo               # the whole story in one shot (validate + predict + explain + readiness)
sbc-validator walk <config>      # guided end-to-end tour: ingest -> each domain -> verdict -> predicted call
sbc-validator serve              # the live dashboard at http://127.0.0.1:8787
sbc-validator validate <config>  --ruleset ~/projects/sbc-validator/rulesets/ms_direct_routing_2026-06.json
sbc-validator simulate <config>  --ruleset ...    # predict the call flow, name the symptom
sbc-validator explain  <capture.pcap>             # post-mortem a packet capture
sbc-validator diff     <active> <standby>         # HA config drift between two nodes
sbc-validator fleet    <dir>     --ruleset ...    # "X of N SBCs ready for the 2026 CA migration"
sbc-validator report   --results results --out fleet-report.html   # the leave-behind
```

Add `--html report.html` to `validate` for a self-contained customer report, or
`--json` for machine output. `--help` on any command lists every flag.

## Live demo sequence (what to type, what shows, what to say)

1. **`sbc-validator demo`**
   Shows the 6-SBC fleet table, a predicted NO_CONNECT call, an explained 488
   rejection, a security-exposed SBC, and "3 of 6 ready".
   Say: *"One command validates a mixed multi-vendor fleet, predicts a call dying
   at the TLS handshake, diagnoses a capture, and rolls up 2026 readiness."*

2. **Double-click the Desktop launcher** (or `sbc-validator serve`)
   The dashboard opens. Click a BLOCK row, drill into the findings.
   Say: *"Same data, live. Every verdict is deterministic, not an LLM guess."*

3. **Walk one finding** (e.g. sbc01: missing 2026 root CA -> BLOCK).
   Say: *"This is the wedge: Microsoft's 2026 root-CA migration hard-stops the
   handshake. We catch it from config, before the outage."*

## If something errors (recovery, you stay calm)

- A bad/truncated config does NOT crash it; it prints a clean one-line error and a
  non-zero exit. Just move on.
- Dashboard didn't open? Visit `http://127.0.0.1:8787/sbc_dashboard.html` manually.
- "command not found"? The launcher self-heals on first run (creates the env). Run
  it once more.

## Rebuild the review packet (one command)

Whenever the repo changes and the handoff needs to be current:

```bash
~/projects/sbc-validator/scripts/build-review-packet.sh
```

It regenerates the source tarball, every PDF, and the fleet report from the current
repo HEAD into `~/Desktop/SBC Philip Review/`. The narrative files
(`_READ-ME-FIRST.md`, `AGENDA.md`) are edited by hand; bump their version stamp if
the release changed.
