from pathlib import Path

from finding_vetter.core import parse_report, vet


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
