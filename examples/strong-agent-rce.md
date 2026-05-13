# Unauthenticated command execution through agent tool endpoint

Severity: Critical

Affected: sample-agent-repo current HEAD.
Tested on: bundled example repo in default configuration.
Attack surface: HTTP API exposed by the server routes.

A remote unauthenticated attacker can POST to `/api/tools/run` in the default server configuration.

Affected files: `server/tools.py`, `server/routes.py`

Attacker: remote unauthenticated user.

Entrypoint: `POST /api/tools/run`

Boundary crossed: unauthenticated HTTP caller can invoke an agent-only command tool without user approval.

Trusted component: `run_command()` passes request JSON into subprocess.

Root cause: `ROUTES` exposes `POST /api/tools/run` directly to `run_command()`, which calls `subprocess.run(..., shell=True)` without authentication, authorization, or approval.

Exploit chain: HTTP request -> JSON `cmd` -> route table -> `run_command()` -> shell.

Impact: host command execution as the server user.

PoC:

```bash
curl -s http://127.0.0.1:8000/api/tools/run -d '{"cmd":"id > /tmp/verifymate-poc"}'
test -f /tmp/verifymate-poc && rm /tmp/verifymate-poc
```

Expected result: `/tmp/verifymate-poc` is created and then removed, demonstrating a safe side effect.

Fix: require authentication and explicit user approval before invoking the tool, and replace shell execution with an allowlisted argv runner using `shell=False`.
