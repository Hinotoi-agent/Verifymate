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


def test_repo_grounding_check_reports_line_backed_ratio(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "api.py").write_text(
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "@app.post('/api/run')\n"
        "def run_command():\n"
        "    import subprocess\n"
        "    cmd = request.json['cmd']\n"
        "    return subprocess.run(cmd, shell=True)\n",
        encoding="utf-8",
    )
    report = tmp_path / "finding.md"
    report.write_text(
        "# Command execution\n\n"
        "Severity: High\n\n"
        "Affected files: `api.py`\n\n"
        "Entrypoint: `POST /api/run`\n\n"
        "Attacker: remote unauthenticated user controls `cmd` and reaches `run_command()`.\n\n"
        "Root cause: attacker-controlled `cmd` flows to subprocess with shell=True.\n\n"
        "PoC: curl /api/run with expected result and cleanup.\n\n"
        "Impact: remote command execution on the server.\n\n"
        "Fix: validate input and avoid shell=True.\n",
        encoding="utf-8",
    )

    result = vet(repo, report)
    repo_grounding = next(check for check in result.checks if check["id"] == "repo_grounding")

    assert repo_grounding["status"] == "pass"
    assert repo_grounding["category"] == "repo_grounding"
    assert repo_grounding["blocking"] == "true"
    assert "4/4" in repo_grounding["detail"]
    assert "api.py:1" in repo_grounding["evidence"]
    assert "api.py:3" in repo_grounding["evidence"]
    assert "api.py:4" in repo_grounding["evidence"]
    assert "api.py:7" in repo_grounding["evidence"]

    markdown = render_markdown(result)
    assert "## Checker result" in markdown
    assert "Repo grounding" in markdown


def test_attacker_path_check_fails_when_only_sink_is_named(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "worker.py").write_text(
        "import subprocess\n\n"
        "def run_command(cmd):\n"
        "    return subprocess.run(cmd, shell=True)\n",
        encoding="utf-8",
    )
    report = tmp_path / "finding.md"
    report.write_text(
        "# Command execution\n\n"
        "Severity: High\n\n"
        "Affected files: `worker.py`\n\n"
        "`run_command()` uses subprocess with shell=True, so this is RCE.\n\n"
        "PoC: curl /run\n",
        encoding="utf-8",
    )

    result = vet(repo, report)
    attacker_path = next(check for check in result.checks if check["id"] == "attacker_path")

    assert attacker_path["status"] == "fail"
    assert attacker_path["category"] == "attacker_path"
    assert attacker_path["blocking"] == "true"
    assert "attacker input" in attacker_path["detail"]
    assert "entrypoint" in attacker_path["detail"]
    assert "source-to-sink" in attacker_path["detail"]


def test_attacker_path_check_passes_for_entrypoint_input_sink_chain(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "api.py").write_text(
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "@app.post('/api/run')\n"
        "def run_command():\n"
        "    import subprocess\n"
        "    cmd = request.json['cmd']\n"
        "    return subprocess.run(cmd, shell=True)\n",
        encoding="utf-8",
    )
    report = tmp_path / "finding.md"
    report.write_text(
        "# Command execution\n\n"
        "Severity: High\n\n"
        "Affected files: `api.py`\n\n"
        "Entrypoint: `POST /api/run`\n\n"
        "Attacker: remote unauthenticated user controls the `cmd` parameter.\n\n"
        "Root cause: source-to-sink path is request.json['cmd'] -> subprocess.run(cmd, shell=True).\n\n"
        "PoC: curl /api/run with expected result and cleanup.\n\n"
        "Impact: remote command execution on the server.\n\n"
        "Fix: validate input and invoke commands without a shell.\n",
        encoding="utf-8",
    )

    result = vet(repo, report)
    attacker_path = next(check for check in result.checks if check["id"] == "attacker_path")

    assert attacker_path["status"] == "pass"
    assert "attacker input, entrypoint, sink, and source-to-sink explanation" in attacker_path["detail"]
