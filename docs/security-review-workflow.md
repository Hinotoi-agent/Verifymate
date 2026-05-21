# Security review workflow integration

Verifymate is intended to run as a deterministic evidence gate inside an OSS security-review workflow. It does not prove a vulnerability and does not write the report for you; it identifies whether a draft has enough repo-grounded evidence to be worth filing, patching, or escalating.

## Recommended workflow

1. Clone or refresh the target repository in a temporary checkout.
2. Draft the finding in Markdown beside the vault note or issue workspace.
3. Run Verifymate against the draft and current checkout.
4. Store both Markdown and JSON outputs beside the draft.
5. Spend review time only on failed or warned checks.
6. Re-run Verifymate after adding missing evidence or changing profile.

```bash
verifymate finding.md \
  --repo /tmp/target-repo \
  --github owner/repo \
  --profile preflight \
  --out finding.verifymate.md

verifymate finding.md \
  --repo /tmp/target-repo \
  --github owner/repo \
  --profile preflight \
  --json \
  --out finding.verifymate.json
```

## Profile choices

- `preflight`: default evidence bar before deeper manual review.
- `cve-request`: stricter CVE/VulnCheck-style readiness check. Use this before filing a CVE request or sending a formal disclosure draft.
- `github-pr`: patch-readiness check for public security-hardening PRs.
- `internal-note`: vault triage mode. It can downgrade incomplete repro/source-to-sink evidence to warnings, but should not make a weak draft fileable.

## Vault artifact convention

For a finding draft named `finding.md`, store:

- `finding.verifymate.md`: human-readable verdict, missing evidence, checklist, and evidence locations.
- `finding.verifymate.json`: machine-readable result for dashboards or follow-up automation.

Suggested directory shape:

```text
Finding Title/
├── finding.md
├── finding.verifymate.md
├── finding.verifymate.json
└── repro-output.txt
```

## Security-review checks

Every security-review pass should treat operator-data safety as a first-class check when a draft involves cleanup, reset, archive extraction, generated artifacts, seed corpora, or output directories. Verifymate emits `destructive_action_safety` to require:

- validation before destructive side effects such as recursive delete, reset, overwrite, or extraction;
- source/input and output path invariants, including refusal of source-as-output, output ancestors, filesystem root, user home, and repository roots;
- regression proof that unsafe paths are rejected without deleting existing operator/project data;
- a positive regression that valid dedicated output directories still work when that behavior is part of the workflow.

## Gate interpretation

- `PASS`: sufficient deterministic evidence for the selected profile. Still requires human review.
- `DUPLICATE_RISK`: evidence may be sufficient, but prior-art/duplicate risk needs manual review.
- `NEEDS_WORK`: promising draft with missing evidence. Fix the listed gaps before filing.
- `WEAK`: sink-only or boundary-weak claim. Reproduce or narrow the claim before spending more review time.
- `INVALID`: repository grounding failed, usually because cited files are absent on the current checkout.

Use `--strict` in automation when a non-fileable verdict should fail the step:

```bash
verifymate finding.md --repo /tmp/target-repo --github owner/repo --profile cve-request --strict
```
