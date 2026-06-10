# SBC-AutoOps as Your Pre-Commit Control

**Who this page is for:** voice and UC teams under an automation mandate. If your
organization requires scripted SBC configuration and provisioning (PowerShell,
Python, Ansible, Terraform) and your change-management procedure must show an
independent check before a config reaches production, this is the integration page.

This is the workflow regulated buyers already describe in their own words. A current
interdealer-broker voice engineering role (MiFID II shop, AudioCodes plus Cisco CUBE,
AWS migration in flight) lists as a core duty: "Develop and maintain automation
scripts (PowerShell, Python, or similar) for: SBC configuration and provisioning.
Monitoring and alerting workflows." SBC-AutoOps is the verification step inside that
exact pipeline: deterministic, air-gapped, and it never touches the SBC.

## The control, in one sentence

Every SBC configuration change passes `sbc-validator validate --fail-on review`
before deployment; the signed, version-stamped verdict is retained as the audit
artifact for the change record.

## What we are, and are not

| We are | We are not |
|---|---|
| The check in front of your deploy step | The deployer (we never push to an SBC) |
| Deterministic verdicts (PASS / REVIEW / BLOCK) | An AI guessing at your config |
| Air-gapped: runs where the config lives | A SaaS your config is uploaded to |
| A signed, version-stamped audit artifact | Continuous monitoring (that is roadmap, stated honestly) |

## Integration recipes (all in `examples/ci/`)

1. **GitHub Actions** (`sbc-pre-deploy-gate.yml`): PRs touching `sbc-configs/**`
   fail when the verdict is REVIEW or worse. A broken Direct Routing config
   cannot merge.
2. **Terraform** (`terraform-sbc-gate.tf`): a `terraform_data` gate with a
   `local-exec` validate step; your deploy resource depends on it, so an apply
   can never run against an unvalidated config.
3. **Ansible** (`ansible-sbc-gate.yml`): render the candidate, validate with
   `--json --out` (the retained audit report), and only then reach your vendor
   deploy task.
4. **Golden-config drift tripwire** (`drift-check.sh`): a cron/CI loop running
   `sbc-validator diff <golden> <current> --fail-on any`. No daemon, no agent on
   the SBC; you keep exporting configs the way you already do. When drift is
   intended, validate the new export and promote it to golden.

## The audit story (why this satisfies the control requirement)

- **Deterministic:** the same config and the same ruleset always produce the same
  verdict. There is no model temperature in the verdict path.
- **Signed rules:** validation logic facts (the 2026 roots, TLS floor, cipher
  allowlist) ship in an Ed25519-signed bundle with rollback refusal, so the
  evidence of WHAT was checked is itself tamper-evident.
- **Version-stamped:** every report carries the ruleset version and timestamp,
  so a change record proves which rule regime the config was validated against.
- **Data boundary:** raw configs never leave your environment. The gate runs
  air-gapped (`docker run --network none` works), which is what makes it usable
  inside a regulated trust boundary in the first place.

## Mapping to common frameworks (indicative, not legal advice)

| Requirement family | Where the control lands |
|---|---|
| MiFID II call-recording continuity | Domain C (TLS/SRTP) blockers stop a change that would silently break recorded trader voice |
| Change-management evidence (SOX-style, FINRA) | The retained `--json --out` verdict per change, ruleset-stamped |
| CJIS / HIPAA encrypted-media posture | Domains C and D findings (SRTP, media trust path, NAT exposure) |
| "Minimize human error in configuration changes" mandates | The gate itself: scripted, deterministic, fails closed |

## Honest limits

The gate validates what a configuration can prove. It does not verify that an
arbitrary SIP header-rewrite regex is semantically correct (no static tool can),
it stays silent where a vendor export does not carry the relevant facts, and it
does not monitor a running SBC. Pre-deployment validation, call-flow simulation,
capture post-mortems, HA and golden drift, and fleet rollups are what ship today.
