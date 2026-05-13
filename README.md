# Verifymate

<p align="center">
  <img src="assets/verifymate-logo.svg" alt="Verifymate chess-knight verification logo" width="180">
</p>

**Verifymate** is a lightweight, repo-grounded CLI that helps security researchers and AI agents verify vulnerability reports before filing them.

It is intentionally **not** a full static analyzer or an automatic vulnerability prover. Instead, it answers the practical pre-submission question:

> Will this finding survive the first questions a maintainer will ask?

Verifymate is useful when you have a draft security finding, AI-generated report, bug bounty note, or disclosure candidate and want a quick sanity check against the real repository.

## Why Verifymate?

Security reports often fail for preventable reasons:

- the referenced file, symbol, endpoint, or code path does not exist anymore
- the report describes a dangerous capability but not an attacker path
- agent/tool functionality is mislabeled as RCE without proving a boundary bypass
- a Critical RCE claim lacks a safe repro, tested version, or root-cause chain
- similar issues are already public in GitHub issues or PRs

Verifymate acts like a checklist-driven review partner: it compares the report to a checkout, highlights confirmed evidence, flags weak spots, and lists the questions a maintainer is likely to ask.

## What it checks

- Referenced files exist on the current checkout.
- Referenced symbols, strings, and endpoints appear in the repo.
- The report includes an attacker model.
- The report includes a PoC/repro indicator.
- Dangerous capability terms exist in the repo.
- Agent/tool context is detected so intended functionality is not mislabeled as RCE.
- Critical/High RCE reports include MADBugs-style proof context:
  - affected/tested version or current commit
  - default attack surface / reachability
  - root cause and source-to-sink path
  - exploit chain from attacker input to impact
  - safe PoC side effect and cleanup
  - concise fix or mitigation guidance
- Optional simple GitHub issue/PR duplicate search via `gh`.

## Install locally

```bash
python -m pip install -e .
```

## Usage

```bash
verifymate finding.md --repo /path/to/repo
```

Try the bundled toy examples:

```bash
verifymate examples/weak-agent-rce.md --repo examples/sample-agent-repo
verifymate examples/strong-agent-rce.md --repo examples/sample-agent-repo
```

Optional duplicate search:

```bash
verifymate finding.md --repo /path/to/repo --github owner/repo
```

JSON output:

```bash
verifymate finding.md --repo /path/to/repo --json
```

Strict CI-friendly exit codes:

```bash
verifymate finding.md --repo /path/to/repo --strict
```

By default, completed vetting returns exit code `0` for all known verdicts so the CLI can be used interactively. With `--strict`, only `PASS` and `DUPLICATE_RISK` return `0`; `NEEDS_WORK`, `WEAK`, and `INVALID` return `2`.

Generate starter report templates:

```bash
verifymate --template general --out finding.md
verifymate --template critical-rce --out critical-rce.md
verifymate --template agent-rce --out agent-rce.md
```

Templates include the evidence sections Verifymate expects, including affected/tested version, attack surface, source-to-sink root cause, safe PoC, impact, and fix guidance.

The legacy `finding-vetter` console command is still available as an alias for compatibility.

## Verdicts

- `PASS`: repo-grounded enough to file, though humans may still ask follow-ups.
- `NEEDS_WORK`: plausible, but missing proof such as a minimal repro or RCE context.
- `WEAK`: dangerous code exists, but attacker path, impact, or boundary is unclear.
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

For Critical/High RCE claims, Verifymate also looks for the compact evidence pattern that appears repeatedly in strong vulnerability writeups: affected/tested version, default attack surface, root-cause code path, attacker-input-to-impact chain, safe PoC side effect with cleanup, and concise fix guidance.

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
# Verifymate Result

Verdict: **WEAK**

## One-line reason

This appears to involve agent/tool functionality, but the report does not prove unauthorized boundary crossing.

## Maintainer will ask

1. Is this API intended for agent/tool use, and if so what unauthorized boundary is bypassed?
2. Who can reach the command/code execution sink in default configuration?
3. Is there authentication, authorization, user approval, or sandboxing before execution?
```

## Design principle

Keep Verifymate as a repo-grounded report reviewer, not an automatic vulnerability prover.
