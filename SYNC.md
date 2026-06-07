# Syncing the validator with the dashboard

Three pieces, fully local:

```
sbc-validator validate <config> --out results/ ...   # 1. write each run
python -m sbc_validator.tools.build_dashboard_data results/ -o dashboard_data.json   # 2. aggregate
# 3. open sbc_dashboard.html, click "Load dashboard_data.json"
```

## 1. Produce results

Run the validator with `--out` (and optionally `--site`). Each run is written to
`results/<sbc>/<timestamp>.json`, preserving history:

```bash
sbc-validator validate samples/audiocodes_min.ini \
    --ruleset rulesets/ms_direct_routing_2026-06.json \
    --out results/ --site EU-West
```

The per-run file is the same record as `--json`, plus `sbc`, `site`,
`validated_at`, and a `domain` (B/C/D/E) on every finding.

## 2. Aggregate into the dashboard payload

```bash
# customer-internal view (FQDNs, sites, full finding detail):
python -m sbc_validator.tools.build_dashboard_data results/ -o dashboard_data.json

# cross-tenant / hosted view (org tokens, counts only — no FQDN/site/detail):
python -m sbc_validator.tools.build_dashboard_data results/ -o dashboard_data.json \
    --anon --org-salt <your-org-salt>
```

This takes the latest run per SBC for the fleet table and builds a per-day
open-findings-by-severity trend from the full history. Output:

```json
{ "generated_at": "...", "ruleset_version": "...", "mode": "internal|anon",
  "fleet": [ /* per-SBC reports + a 'top' finding */ ],
  "trend": { "labels": [...], "series": { "CRITICAL":[...], "HIGH":[...], "MEDIUM":[...], "LOW":[...] } } }
```

## 3. Load into the dashboard

Open `sbc_dashboard.html` and click **Load dashboard_data.json** (top-right of
the filter bar), or — if you serve the folder over HTTP — drop the JSON next to
the HTML and it auto-loads on open. The `internal`/`anon` badge reflects which
view you loaded. Until you load anything, it runs on built-in sample data.

## The one decision baked in here

`--anon` is where the trust-boundary call lives. The internal payload shows
hostnames and full remediation detail and must stay inside the customer
environment. The `--anon` payload carries only `check_id` + `severity` + vendor +
ruleset version + a salted token — safe to aggregate cross-tenant. Pick which
the dashboard is fed based on where it's deployed; the HTML renders either.
