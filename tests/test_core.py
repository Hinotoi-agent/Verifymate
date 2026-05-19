from pathlib import Path

from finding_vetter.core import parse_report, redact_sensitive_text, render_markdown, vet


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
        check["name"] == "attacker_model" and check["status"] == "fail" for check in result.checks
    )


def test_missing_file_invalid(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    report = tmp_path / "finding.md"
    report.write_text(
        "# Bug\n\nAffected files: `missing/file.py`\n\nPoC: curl /x\nAttacker: remote unauthenticated\n",
        encoding="utf-8",
    )
    result = vet(repo, report)
    assert result.verdict == "INVALID"
    assert any("not found" in m for m in result.missing)


def test_file_refs_accept_line_and_github_anchor_suffixes(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "server").mkdir()
    (repo / "server" / "api.py").write_text(
        "from flask import Flask\napp = Flask(__name__)\n@app.post('/run')\ndef run_command():\n    pass\n",
        encoding="utf-8",
    )
    (repo / "server" / "auth.py").write_text(
        "def check_auth():\n    return True\n", encoding="utf-8"
    )
    report = tmp_path / "finding.md"
    report.write_text(
        "# Bug\n\n"
        "Affected files: `server/api.py:4` and `server/auth.py#L1-L2`\n\n"
        "Entrypoint: `POST /run`\n\n"
        "Attacker: remote unauthenticated user controls the request.\n\n"
        "Root cause: request reaches `run_command()`.\n\n"
        "PoC: curl /run with expected result and cleanup.\n\n"
        "Impact: authorization bypass.\n\n"
        "Fix: require authentication.\n",
        encoding="utf-8",
    )

    result = vet(repo, report)

    assert "server/api.py" in result.parsed["files"]
    assert "server/auth.py" in result.parsed["files"]
    assert not any("server/api.py:4" in item for item in result.missing)
    assert not any("server/auth.py#L1-L2" in item for item in result.missing)
    assert any(
        item["kind"] == "file" and item["file"] == "server/api.py"
        for item in result.evidence_locations
    )
    assert any(
        item["kind"] == "file" and item["file"] == "server/auth.py"
        for item in result.evidence_locations
    )


def test_parse_endpoint_and_attacker(tmp_path: Path):
    report = tmp_path / "finding.md"
    report.write_text(
        "# Bug\n\nEntrypoint: `POST /api/tools/run`\nAttacker: remote unauthenticated user\nPoC: curl\n",
        encoding="utf-8",
    )
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
    assert any(
        item["kind"] == "command execution" and item["term"] == "shell=True"
        for item in result.evidence_locations
    )

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
        "import subprocess\n\ndef run_command(cmd):\n    return subprocess.run(cmd, shell=True)\n",
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
    assert (
        "attacker input, entrypoint, sink, and source-to-sink explanation"
        in attacker_path["detail"]
    )


def test_source_to_sink_chain_check_requires_line_backed_source_and_sink(tmp_path: Path):
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
        "Root cause: source-to-sink path is `cmd` -> `subprocess.run`.\n\n"
        "PoC: curl /api/run with expected result and cleanup.\n\n"
        "Impact: remote command execution on the server.\n\n"
        "Fix: validate input and avoid shell=True.\n",
        encoding="utf-8",
    )

    result = vet(repo, report)

    chain = next(check for check in result.checks if check["id"] == "source_to_sink_chain")
    assert chain["status"] == "pass"
    assert chain["blocking"] == "true"
    assert "api.py:6" in chain["detail"]
    assert "api.py:7" in chain["detail"]
    assert any(item["kind"] == "source" and item["term"] == "cmd" for item in result.evidence_locations)
    assert any(item["kind"] == "sink" and item["term"] == "subprocess.run" for item in result.evidence_locations)


def test_source_to_sink_chain_fails_when_source_is_not_in_checkout(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "api.py").write_text(
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "@app.post('/api/run')\n"
        "def run_command(command):\n"
        "    import subprocess\n"
        "    return subprocess.run(command, shell=True)\n",
        encoding="utf-8",
    )
    report = tmp_path / "finding.md"
    report.write_text(
        "# Command execution\n\n"
        "Severity: High\n\n"
        "Affected files: `api.py`\n\n"
        "Entrypoint: `POST /api/run`\n\n"
        "Attacker: remote unauthenticated user controls the `cmd` parameter.\n\n"
        "Root cause: source-to-sink path is `cmd` -> `subprocess.run`.\n\n"
        "PoC: curl /api/run with expected result and cleanup.\n\n"
        "Impact: remote command execution on the server.\n\n"
        "Fix: validate input and avoid shell=True.\n",
        encoding="utf-8",
    )

    result = vet(repo, report)

    chain = next(check for check in result.checks if check["id"] == "source_to_sink_chain")
    assert result.verdict == "NEEDS_WORK"
    assert chain["status"] == "fail"
    assert chain["blocking"] == "true"
    assert "line-backed source" in chain["detail"]


def test_owasp_rationalization_maps_web_and_llm_categories(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "agent.py").write_text(
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "@app.post('/api/agent')\n"
        "def agent_run():\n"
        "    import subprocess\n"
        "    prompt = request.json['prompt']\n"
        "    return subprocess.run(prompt, shell=True)\n",
        encoding="utf-8",
    )
    report = tmp_path / "finding.md"
    report.write_text(
        "# Prompt injection to tool command execution\n\n"
        "Severity: High\n\n"
        "Affected files: `agent.py`\n\n"
        "Entrypoint: `POST /api/agent`\n\n"
        "Attack surface: default web API reachable by remote unauthenticated users.\n\n"
        "Attacker: remote unauthenticated user controls the prompt parameter and bypasses approval.\n\n"
        "Root cause: source-to-sink path is request.json['prompt'] -> subprocess.run(prompt, shell=True).\n\n"
        "PoC: curl /api/agent with expected result and cleanup.\n\n"
        "Impact: prompt injection leads to remote command execution and privilege misuse.\n\n"
        "Fix: require authentication, approval gating, and avoid shell=True.\n",
        encoding="utf-8",
    )

    result = vet(repo, report)
    web = next(check for check in result.checks if check["id"] == "owasp_top_10")
    llm = next(check for check in result.checks if check["id"] == "owasp_llm_top_10")

    assert web["status"] == "pass"
    assert web["category"] == "owasp"
    assert "A01:2021-Broken Access Control" in web["detail"]
    assert "A03:2021-Injection" in web["detail"]
    assert llm["status"] == "pass"
    assert llm["category"] == "owasp_llm"
    assert "LLM01:2025 Prompt Injection" in llm["detail"]
    assert "LLM06:2025 Excessive Agency" in llm["detail"]

    markdown = render_markdown(result)
    assert "### OWASP rationalization" in markdown
    assert "OWASP Top 10" in markdown
    assert "OWASP Top 10 for LLM Applications" in markdown


def test_owasp_rationalization_warns_when_no_category_fits(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "README.md").write_text("# docs\n", encoding="utf-8")
    report = tmp_path / "finding.md"
    report.write_text(
        "# Ambiguous bug\n\n"
        "Affected files: `README.md`\n\n"
        "Attacker: remote user.\n\n"
        "PoC: curl /health\n",
        encoding="utf-8",
    )

    result = vet(repo, report)
    web = next(check for check in result.checks if check["id"] == "owasp_top_10")
    llm = next(check for check in result.checks if check["id"] == "owasp_llm_top_10")

    assert web["status"] == "warn"
    assert "No strong OWASP Top 10 mapping" in web["detail"]
    assert llm["status"] == "warn"
    assert "No strong OWASP LLM Top 10 mapping" in llm["detail"]


def test_cve_request_profile_requires_disclosure_ready_evidence(tmp_path: Path):
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
        "PoC: curl /api/run.\n\n"
        "Impact: remote command execution on the server.\n",
        encoding="utf-8",
    )

    result = vet(repo, report, profile="cve-request")

    profile = next(check for check in result.checks if check["id"] == "profile")
    safe_repro = next(check for check in result.checks if check["id"] == "profile_cve_safe_repro")
    duplicate_review = next(
        check for check in result.checks if check["id"] == "profile_cve_duplicate_review"
    )
    fix_guidance = next(
        check for check in result.checks if check["id"] == "profile_cve_fix_guidance"
    )

    assert result.parsed["profile"] == "cve-request"
    assert result.verdict == "NEEDS_WORK"
    assert "profile_cve_safe_repro" in result.reason
    assert profile["detail"] == "Using `cve-request` validation profile."
    assert safe_repro["status"] == "fail"
    assert safe_repro["blocking"] == "true"
    assert duplicate_review["status"] == "fail"
    assert fix_guidance["status"] == "fail"


def test_cve_request_profile_accepts_duplicate_search_option(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "api.py").write_text("def ok():\n    pass\n", encoding="utf-8")
    report = tmp_path / "finding.md"
    report.write_text(
        "# Auth bypass\n\n"
        "Affected files: `api.py`\n\n"
        "Confirmed against current HEAD.\n\n"
        "Attack surface: remote API.\n\n"
        "Attacker: remote unauthenticated user controls the request.\n\n"
        "Root cause: source-to-sink path reaches auth bypass.\n\n"
        "PoC: safe code-path proof with expected result and cleanup.\n\n"
        "Impact: authorization bypass.\n\n"
        "Fix: require authentication.\n",
        encoding="utf-8",
    )

    result = vet(repo, report, owner_repo="owner/repo", profile="cve-request")

    duplicate_review = next(
        check for check in result.checks if check["id"] == "profile_cve_duplicate_review"
    )
    assert duplicate_review["status"] == "pass"


def test_internal_note_profile_relaxes_triage_debt_but_preserves_needs_work(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "worker.py").write_text(
        "import subprocess\n\ndef run_command(cmd):\n    return subprocess.run(cmd, shell=True)\n",
        encoding="utf-8",
    )
    report = tmp_path / "finding.md"
    report.write_text(
        "# Possible command execution\n\n"
        "Severity: High\n\n"
        "Affected files: `worker.py`\n\n"
        "Remote attacker may control input reaching `run_command()`.\n",
        encoding="utf-8",
    )

    result = vet(repo, report, profile="internal-note")

    repro = next(check for check in result.checks if check["id"] == "repro")
    attacker_path = next(check for check in result.checks if check["id"] == "attacker_path")
    assert result.verdict == "NEEDS_WORK"
    assert repro["status"] == "warn"
    assert repro["blocking"] == "false"
    assert attacker_path["status"] == "warn"
    assert attacker_path["blocking"] == "false"


def test_internal_note_profile_keeps_missing_source_to_sink_non_fileable(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "worker.py").write_text(
        "import subprocess\n\ndef run_command(cmd):\n    return subprocess.run(cmd, shell=True)\n",
        encoding="utf-8",
    )
    report = tmp_path / "finding.md"
    report.write_text(
        "# Possible command execution\n\n"
        "Severity: High\n\n"
        "Affected files: `worker.py`\n\n"
        "Attacker: remote user may control command text.\n\n"
        "PoC: call run_command with a harmless command and confirm expected result.\n\n"
        "Impact: command execution in the worker process.\n",
        encoding="utf-8",
    )

    result = vet(repo, report, profile="internal-note")

    attacker_path = next(check for check in result.checks if check["id"] == "attacker_path")
    assert result.verdict == "NEEDS_WORK"
    assert "not fileable yet" in result.reason
    assert attacker_path["status"] == "warn"
    assert attacker_path["blocking"] == "false"


def test_severity_calibration_blocks_high_defense_in_depth_github_pr(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "adapter.py").write_text(
        "from pathlib import Path\n"
        "def save(provider_filename):\n"
        "    return Path('media') / provider_filename\n",
        encoding="utf-8",
    )
    report = tmp_path / "finding.md"
    report.write_text(
        "# Path containment hardening\n\n"
        "Severity: High\n\n"
        "Affected files: `adapter.py`\n\n"
        "Attack surface: provider media adapter.\n\n"
        "Attacker: remote user may influence filenames, but here the value is server-side metadata and not user-controlled.\n\n"
        "Root cause: source-to-sink path is provider filename -> media path write.\n\n"
        "PoC: safe proof with expected result and cleanup.\n\n"
        "Impact: path traversal if the upstream provider returned traversal names.\n\n"
        "Fix: sanitize filename once at the unified write point. This is defense-in-depth hardening.\n",
        encoding="utf-8",
    )

    result = vet(repo, report, profile="github-pr")

    severity = next(check for check in result.checks if check["id"] == "severity_calibration")
    assert result.verdict == "NEEDS_WORK"
    assert severity["status"] == "fail"
    assert severity["blocking"] == "true"
    assert "defense-in-depth" in severity["detail"]
    assert "not user-controlled" in severity["detail"]


def test_severity_calibration_accepts_low_defense_in_depth_pr(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "adapter.py").write_text(
        "from pathlib import Path\n"
        "def save(provider_filename):\n"
        "    return Path('media') / provider_filename\n",
        encoding="utf-8",
    )
    report = tmp_path / "finding.md"
    report.write_text(
        "# Path containment hardening\n\n"
        "Severity: Low\n\n"
        "Affected files: `adapter.py`\n\n"
        "Attack surface: provider media adapter.\n\n"
        "Attacker: remote user may influence filenames only if upstream provider metadata is unsafe.\n\n"
        "Root cause: source-to-sink path is provider filename -> media path write.\n\n"
        "PoC: safe proof with expected result and cleanup.\n\n"
        "Impact: defense-in-depth path containment.\n\n"
        "Fix: sanitize filename once at the unified write point.\n",
        encoding="utf-8",
    )

    result = vet(repo, report, profile="github-pr")

    severity = next(check for check in result.checks if check["id"] == "severity_calibration")
    assert severity["status"] == "pass"
    assert severity["blocking"] == "false"


def test_evidence_snippets_redact_secret_values(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "config.py").write_text(
        "API_KEY = 'live-secret-value'\n"
        "AUTHORIZATION = 'Bearer header-secret'\n"
        "DATABASE_URL = 'postgres://user:pass@db.local/app'\n",
        encoding="utf-8",
    )
    report = tmp_path / "finding.md"
    report.write_text(
        "# Secret exposure\n\n"
        "Affected files: `config.py`\n\n"
        "Attacker: remote authenticated user controls request parameters.\n\n"
        "Root cause: source-to-sink path reaches `API_KEY`.\n\n"
        "PoC: safe proof with expected result and cleanup.\n\n"
        "Impact: credential disclosure and secret exposure.\n\n"
        "Fix: remove hardcoded secrets.\n",
        encoding="utf-8",
    )

    result = vet(repo, report)
    rendered = render_markdown(result)

    snippets = "\n".join(item["snippet"] for item in result.evidence_locations)
    assert "[REDACTED]" in snippets
    assert "live-secret-value" not in snippets
    assert "header-secret" not in snippets
    assert "user:pass" not in snippets
    assert "live-secret-value" not in rendered
    assert "header-secret" not in rendered
    assert "user:pass" not in rendered


def test_redact_sensitive_text_handles_common_secret_shapes():
    text = (
        "api_token=abc123 Authorization: Bearer deadbeef "
        "postgres://app:secret@db.internal/service password: hunter2"
    )

    redacted = redact_sensitive_text(text)

    assert "abc123" not in redacted
    assert "deadbeef" not in redacted
    assert "app:secret" not in redacted
    assert "hunter2" not in redacted
    assert redacted.count("[REDACTED]") >= 4
