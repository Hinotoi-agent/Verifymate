# Unauthenticated command execution through agent tool endpoint

Severity: Critical

A remote unauthenticated attacker can POST to `/api/tools/run` in the default server configuration.

Affected files: `server/tools.py`, `server/routes.py`

Attacker: remote unauthenticated user.

Entrypoint: `POST /api/tools/run`

Boundary crossed: unauthenticated HTTP caller can invoke an agent-only command tool without user approval.

Trusted component: `run_command()` passes request JSON into subprocess.

Impact: host command execution as the server user.

PoC:

```bash
curl -s http://127.0.0.1:8000/api/tools/run -d '{"cmd":"id > /tmp/finding-vetter-poc"}'
```

Proof: `/tmp/finding-vetter-poc` is created and then removed.
