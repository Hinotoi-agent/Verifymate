from pathlib import Path

from finding_vetter.core import vet


def _write_rce_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "server").mkdir(parents=True)
    (repo / "server" / "handler.py").write_text(
        "import subprocess\n\n"
        "def handle(request):\n"
        "    cmd = request.json['cmd']\n"
        "    return subprocess.run(cmd, shell=True)\n",
        encoding="utf-8",
    )
    return repo


def test_critical_rce_needs_madbugs_style_repro_context(tmp_path: Path):
    repo = _write_rce_repo(tmp_path)
    report = tmp_path / "thin-rce.md"
    report.write_text(
        "# Critical RCE\n\n"
        "Severity: Critical\n\n"
        "Affected files: `server/handler.py`\n\n"
        "Attacker: remote unauthenticated user.\n\n"
        "Entrypoint: `POST /run`\n\n"
        "Boundary crossed: unauthenticated HTTP caller reaches subprocess.\n\n"
        "PoC: curl http://target/run -d '{\"cmd\":\"id\"}'\n",
        encoding="utf-8",
    )

    result = vet(repo, report)

    assert result.verdict == "NEEDS_WORK"
    assert any("affected/tested version" in item.lower() for item in result.missing)
    assert any("root-cause" in item.lower() for item in result.missing)
    assert any("safe side effect" in q.lower() for q in result.questions)


def test_madbugs_style_rce_report_passes_with_versions_chain_and_fix(tmp_path: Path):
    repo = _write_rce_repo(tmp_path)
    report = tmp_path / "grounded-rce.md"
    report.write_text(
        "# Unauthenticated command execution in handler\n\n"
        "Severity: Critical\n\n"
        "Affected: demo-agent <= 1.2.3.\n"
        "Tested on: commit abc123 in default configuration.\n"
        "Attack surface: HTTP API exposed on port 8000.\n\n"
        "Affected files: `server/handler.py`\n\n"
        "Attacker: remote unauthenticated user.\n"
        "Entrypoint: `POST /run`\n"
        "Boundary crossed: unauthenticated HTTP caller can invoke a server-side shell command.\n\n"
        "Root cause: `handle()` copies attacker-controlled JSON into `subprocess.run(..., shell=True)` without auth.\n"
        "Exploit chain: HTTP request -> JSON `cmd` -> `handle()` -> shell.\n"
        "Impact: host command execution as the server user.\n\n"
        "PoC:\n```bash\n"
        "curl http://127.0.0.1:8000/run -d '{\"cmd\":\"id > /tmp/fv-safe-poc\"}'\n"
        "test -f /tmp/fv-safe-poc && rm /tmp/fv-safe-poc\n"
        "```\n\n"
        "Expected result: `/tmp/fv-safe-poc` is created, proving a safe side effect.\n"
        "Fix: require authentication and pass an allowlisted argv array with `shell=False`.\n",
        encoding="utf-8",
    )

    result = vet(repo, report)

    assert result.verdict == "PASS"
    assert any("affected/tested version" in item.lower() for item in result.confirmed)
    assert any("root-cause" in item.lower() for item in result.confirmed)
    assert not any("safe side effect" in item.lower() for item in result.missing)
