# Dashboard Guide

The dashboard is a **local-first fleet view**. It reads the per-run JSON the
validator writes and renders it as a single page. Nothing leaves the host: it is
served from `127.0.0.1`, or opened straight from a file. There is no backend.

## Two ways to open it

**Served (recommended)** - rebuilds live as new validations land:

```bash
sbc-validator validate config.ini --out results      # record one or more runs
sbc-validator serve --results results                # http://127.0.0.1:8787
```

`serve` auto-loads `dashboard_data.json` (rebuilt from `results/` on every
request), so re-running `validate --out results` and refreshing shows new data.

**From a file** - double-click `sbc_dashboard.html`. Because a `file://` page
cannot auto-fetch, click **"⤓ Load dashboard_data.json"** and pick a file you
generated with:

```bash
python -m sbc_validator.tools.build_dashboard_data results -o dashboard_data.json
```

## What each panel shows

| Panel | Reads | Meaning |
|---|---|---|
| **Stat tile** (big number) | verdicts | SBCs blocked from deploy; plus fleet / review / pass counts |
| **Open Findings by Domain** | findings | non-INFO findings per domain A-G + **S** (security) |
| **Open Findings Trend** | per-day history | severity counts over time (one point per day of runs) |
| **Avg Risk Score by Vendor** | risk scores | which vendor's configs are riskiest in this fleet |
| **Verdict donut** | verdicts | BLOCK / REVIEW / PASS split |
| **Severity x Domain heatmap** | findings | where the severity is concentrated (rows = severity, cols = A-G,S) |
| **SBC Fleet table** | latest run per SBC | per-SBC verdict, risk, site, and top finding |

## Controls (all live)

- **Vendor** filter - populated from the loaded data; scopes every panel.
- **Verdict** filter - BLOCK / REVIEW / PASS; scopes every panel.
- **Load dashboard_data.json** - load a payload by hand (for the `file://` case).

The left sidebar (Fleet Overview, Findings, Settings, etc.) is **presentational
framing only** - it sets the operations-console look but is not wired to
sub-pages. The data panels, the two filters, and the loader are the live surface.

## Where the data comes from

```
validate --out results/   ->  results/<sbc>/<timestamp>.json   (one file per run)
                              |
build_dashboard_data  /  serve  ->  { fleet:[...], trend:{...}, mode }
                              |
                          dashboard renders it
```

The trend chart needs history to be interesting: validate over several days (or
several runs) and each day becomes a point. A single demo run shows one point.

## Privacy

`serve` binds to loopback by default. The dashboard only ever reads the local
result JSON (already on the host); raw configs are never sent anywhere. With
`--anon` on the data build, the payload carries tokens instead of FQDNs and no
sites/locators, suitable for a cross-tenant view.
