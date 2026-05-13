# finding-vetter

`finding-vetter` is a small checklist-driven CLI for reviewing AI-generated vulnerability reports against a real repository before filing them.

It is intentionally **not** a full static analyzer. It answers the practical pre-submission question:

> Will this finding survive the first questions a maintainer will ask?

## What it checks

- Referenced files exist on current checkout.
- Referenced symbols/endpoints appear in the repo.
- The report has an attacker model.
- The report has a PoC/repro indicator.
- Dangerous capability terms exist in the repo.
- Agent/tool context is detected so intended functionality is not mislabeled as RCE.
- Optional simple GitHub issue/PR duplicate search via `gh`.

## Install locally

```bash
python -m pip install -e .
```

## Usage

```bash
finding-vetter finding.md --repo /path/to/repo
```

Try the bundled toy example:

```bash
finding-vetter examples/weak-agent-rce.md --repo examples/sample-agent-repo
finding-vetter examples/strong-agent-rce.md --repo examples/sample-agent-repo
```

Optional duplicate search:

```bash
finding-vetter finding.md --repo /path/to/repo --github owner/repo
```

JSON output:

```bash
finding-vetter finding.md --repo /path/to/repo --json
```

## Verdicts

- `PASS`: repo-grounded enough to file, though humans may still ask follow-ups.
- `NEEDS_WORK`: plausible, but missing proof such as a minimal repro.
- `WEAK`: dangerous code exists, but attacker path/impact/boundary is unclear.
- `INVALID`: referenced evidence does not exist or is contradicted by the repo.
- `DUPLICATE_RISK`: likely grounded, but similar public items may exist.

## The six-question model

Every report should answer:

1. What is the attacker-controlled input?
2. What trusted component processes it?
3. What security boundary is crossed?
4. What dangerous action happens?
5. What asset or user is harmed?
6. What proof shows this works on current HEAD?

## Agent/tool API rule

For agent and AI repos, command execution or file access may be intended functionality.

A dangerous agent capability is not a vulnerability unless the report proves at least one boundary failure:

- unauthorized caller can invoke the tool
- prompt injection can trigger the tool
- approval can be bypassed
- sandbox/workspace boundary can be escaped
- one user/workspace can affect another
- secrets or host files can be accessed unexpectedly

## Example output

```markdown
# Finding Vetter Result

Verdict: **WEAK**

## One-line reason

This appears to involve agent/tool functionality, but the report does not prove unauthorized boundary crossing.

## Maintainer will ask

1. Is this API intended for agent/tool use, and if so what unauthorized boundary is bypassed?
2. Who can reach the command/code execution sink in default configuration?
3. Is there authentication, authorization, user approval, or sandboxing before execution?
```

## Design principle

Keep this as a repo-grounded report reviewer, not an automatic vulnerability prover.
