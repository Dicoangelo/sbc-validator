# SBC Validator: Production Plan

Status as of 2026-06-07. The product is a **local-first, sovereignty-first**
diagnostic tool. "Production" here is NOT one cloud deployment: hosting the
engine or dashboard publicly would break the core pitch (raw configs never leave
the customer's VPC). Production = a real distributable the customer runs, plus a
small signed-rule service the publisher runs.

## The three planes

- **Plane A (the product) — engine + local dashboard the CUSTOMER runs** inside
  their VPC. ~80% built (v0.14.0: 4 vendors, validators A-G, validate/simulate/
  explain/diff/fleet, signed+authority-sourced ruleset, CI, Docker, 66 tests).
- **Plane B — the signed-rule service the PUBLISHER runs.** The one legitimately
  hosted backend. Client already speaks HTTPS GET + verify; for v1 this is a
  **signed file on object storage** (S3 / GitHub release asset), not a bespoke API.
- **Plane C — consented anonymized telemetry aggregator** (the data moat).
  Phase 2+. Needs a consent framework and a customer generating data. Not now.

## Hard gates (before "production" is honest)

1. **Signing key.** [DONE 2026-06-07] Dev private key was committed and pinned =
   anyone could forge a "valid" ruleset. Rotated to an offline publisher keypair
   (`~/.sbc-validator/keys/publisher_ed25519.pem`, chmod 600, outside git); pin
   updated; ruleset re-signed; tests moved to ephemeral keys. **REMAINING: scrub
   the old dev key from git history (irreversible force-push) + migrate the
   private key to an HSM before GA.**
2. **Parser fidelity.** Need one real customer / SBC Config Wizard `.ini` to
   prove the AudioCodes parser against full production grammar. External input.
3. **No pilot yet.** Pre-engagement. The design partner defines real requirements;
   do not over-build ahead of one.

## Phase 0 — pilot-ready distributable (the current focus)

Goal: a design partner can `docker run` it air-gapped in their environment.

- [x] **0.1 Key rotation** — offline publisher keypair, pin rotated, ruleset
  re-signed, dev key removed from working tree, tests use an ephemeral `signing_key`
  fixture. (commit: this change)
- [ ] **0.2 Git-history scrub** of the old dev key (separate, explicitly confirmed
  — force-push rewrite; coordinate per parallel-session rules).
- [ ] **0.3 Clean packaging** — fix `pyproject` package-data path (`../rulesets`
  won't ship in a wheel), refresh the stale "A-E" description to A-G, verify
  `pip install .` + `sbc-validator` entrypoint works from a clean venv.
- [ ] **0.4 `sbc-validator serve`** — local web command that serves the dashboard
  + reads `results/` live (auto-refresh), bundled in the container. Kills the
  Desktop-copy drift; the dashboard stays local (never hosted).
- [ ] **0.5 Published Docker image** — tag + push `v0.14.0` to a registry (CI
  already builds and air-gap-tests it).
- [ ] **0.6 VPC runbook** — one page: install, run air-gapped, read reports,
  gate a pipeline. Partner-facing.

## Phase 1 — trust backbone (Plane B)

- [ ] Stand up the signed-ruleset distribution (object storage first; bespoke API
  only if a partner needs scheduled pulls). Client `api_base` already supports it.
- [ ] Re-sign/publish workflow wired from `RULE_AUTHORITY.md`; HSM for the key.
- [ ] Optional: signed-rule freshness SLA + monitoring.

## Phase 2 — pilot + data moat (Plane C)

- [ ] Land a design partner; harden AudioCodes parser on their real config.
- [ ] Consent framework + anonymized aggregator (the cross-tenant benchmark moat).

## Explicitly NOT building yet (avoid premature infra)

- No bespoke rule-service app (object storage suffices for v1).
- No cloud-hosted dashboard (sovereignty: stays local).
- No telemetry aggregator (no consenting customer yet).
- No multi-tenant control plane (no second tenant yet).
