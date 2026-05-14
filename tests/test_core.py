from pathlib import Path

from finding_vetter.core import parse_report, render_markdown, vet


def test_weak_agent_rce_needs_boundary(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "server").mkdir()
    (repo / "server" / "tools.py").write_text(
        "# agent tool\nimport subprocess\ndef run_command(cmd):\n    return subprocess.run(cmd, shell=True)\n",
        encoding="utf-8",
    )
    report = tmp_path / "finding.md"
    report.write_text(
        "# Critical RCE\n\nSeverity: Critical\n\nAffected files: `server/tools.py`\n\n`run_command()` uses subprocess. This is RCE.\n",
        encoding="utf-8",
    )
    result = vet(repo, report)
    assert result.verdict == "WEAK"
    assert "boundary" in result.reason.lower()
    assert any("agent/tool" in q.lower() for q in result.questions)
    assert any(check["name"] == "agent_boundary" for check in result.checks)
    assert any(
        check["name"] == "attacker_model" and check["status"] == "fail"
        for check in result.checks
    )


def test_missing_file_invalid(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    report = tmp_path / "finding.md"
    report.write_text("# Bug\n\nAffected files: `missing/file.py`\n\nPoC: curl /x\nAttacker: remote unauthenticated\n", encoding="utf-8")
    result = vet(repo, report)
    assert result.verdict == "INVALID"
    assert any("not found" in m for m in result.missing)


def test_parse_endpoint_and_attacker(tmp_path: Path):
    report = tmp_path / "finding.md"
    report.write_text("# Bug\n\nEntrypoint: `POST /api/tools/run`\nAttacker: remote unauthenticated user\nPoC: curl\n", encoding="utf-8")
    parsed = parse_report(report)
    assert "POST /api/tools/run" in parsed.endpoints
    assert parsed.has_repro
    assert "remote" in [x.lower() for x in parsed.attacker_mentions]


def test_vet_records_line_level_evidence_locations(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "server.py").write_text(
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "@app.post('/api/run')\n"
        "def run_command():\n"
        "    import subprocess\n"
        "    return subprocess.run('id', shell=True)\n",
        encoding="utf-8",
    )
    report = tmp_path / "finding.md"
    report.write_text(
        "# Command execution\n\n"
        "Severity: High\n\n"
        "Affected files: `server.py`\n\n"
        "Entrypoint: `POST /api/run`\n\n"
        "Attacker: remote unauthenticated user\n\n"
        "PoC: curl /api/run\n\n"
        "`run_command()` reaches subprocess with shell=True.\n",
        encoding="utf-8",
    )

    result = vet(repo, report)

    assert any(
        item["kind"] == "symbol"
        and item["term"] == "run_command"
        and item["file"] == "server.py"
        and item["line"] == "4"
        for item in result.evidence_locations
    )
    assert any(
        item["kind"] == "endpoint" and item["term"] == "POST /api/run" and item["line"] == "3"
        for item in result.evidence_locations
    )
    assert any(item["kind"] == "command execution" and item["term"] == "shell=True" for item in result.evidence_locations)

    markdown = render_markdown(result)
    assert "## Evidence locations" in markdown
    assert "`server.py:4`" in markdown
