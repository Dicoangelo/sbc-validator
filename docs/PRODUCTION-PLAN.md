# SBC Validator: Production Plan

Status as of 2026-06-07. The product is a **local-first, sovereignty-first**
diagnostic tool. "Production" here is NOT one cloud deployment: hosting the
engine or dashboard publicly would break the core pitch (raw configs never leave
the customer's VPC). Production = a real distributable the customer runs, plus a
small signed-rule service the publisher runs.

## The three planes

- **Plane A (the product) — engine + local dashboard the CUSTOMER runs** inside
  their VPC. Built (v0.16.1: 4 vendors, validators A-G plus S, validate/simulate/
  explain/diff/fleet/serve/demo/report, signed+authority-sourced ruleset, CI,
  Docker, 126 tests).
- **Plane B — the signed-rule service the PUBLISHER runs.** The one legitimately
  hosted backend. Client already speaks HTTPS GET + verify; for v1 this is a
  **signed file on object storage** (S3 / GitHub release asset), not a bespoke API.
- **Plane C — consented anonymized telemetry aggregator** (the data moat).
  Phase 2+. Needs a consent framework and a customer generating data. Not now.

## Hard gates (before "production" is honest)

1. **Signing key.** [DONE 2026-06-07] Dev private key was committed and pinned =
   anyone could forge a "valid" ruleset. Rotated to an offline publisher keypair
   (`~/.sbc-validator/keys/publisher_ed25519.pem`, chmod 600, outside git); pin
   updated; ruleset re-signed; tests moved to ephemeral keys. The old key is now
   DEAD (pinned nowhere). **History-scrub DECISION: deferred.** Rewriting history
   to remove an already-neutralized key from a private, single-user, no-clones
   repo is pure downside (irreversible force-push). Correct trigger: scrub
   immediately BEFORE the repo is ever made public. HSM migration before GA.
2. **Parser fidelity.** Need one real customer / SBC Config Wizard `.ini` to
   prove the AudioCodes parser against full production grammar. External input.
3. **No pilot yet.** Pre-engagement. The design partner defines real requirements;
   do not over-build ahead of one.

## Phase 0 — pilot-ready distributable (the current focus)

Goal: a design partner can `docker run` it air-gapped in their environment.

- [x] **0.1 Key rotation** (commit f5b7ae5): offline publisher keypair, pin
  rotated, ruleset re-signed, dev key removed from working tree, tests use an
  ephemeral `signing_key` fixture.
- [~] **0.2 Git-history scrub** — DEFERRED by decision (dead key, private repo,
  no users). Trigger: before going public. See gate 1 above.
- [x] **0.3 Clean packaging** (commit 3721ec8) — broken package-data removed,
  description A-G, clean-venv wheel install verified.
- [x] **0.4 `sbc-validator serve`** (commit 7045ecf) — loopback local dashboard,
  live rebuild from results/, viewer packaged in the wheel + container.
- [x] **0.5 Release pipeline** — `.github/workflows/release.yml` builds + pushes
  the image to ghcr.io ON A TAG only (nothing publishes on ordinary commits),
  with an air-gap smoke on the published image. Cut `vX.Y.Z` to publish.
- [x] **0.6 VPC runbook** — `RUNBOOK.md`, partner-facing: install, air-gapped
  validate, fleet readiness, live dashboard, predict/explain, pre-GA notes.

Phase 0 is functionally complete. What is intentionally NOT done because there
is no pilot yet: the history scrub (0.2), HSM migration, and any Plane B/C infra.
The next real driver is a design partner; everything past Phase 0 waits on one.

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
