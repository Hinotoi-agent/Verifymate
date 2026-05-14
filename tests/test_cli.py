from __future__ import annotations

from pathlib import Path

from finding_vetter.cli import main
from finding_vetter.core import render_report_template


def test_render_critical_rce_template_contains_required_evidence_sections():
    template = render_report_template("critical-rce")

    assert "# Critical RCE report" in template
    assert "## Affected / tested version" in template
    assert "## Attack surface" in template
    assert "## Source-to-sink root cause" in template
    assert "## Safe PoC" in template
    assert "## Fix guidance" in template


def test_cli_template_writes_without_repo_or_report(tmp_path: Path):
    out = tmp_path / "template.md"

    code = main(["--template", "agent-rce", "--out", str(out)])

    assert code == 0
    text = out.read_text(encoding="utf-8")
    assert "Agent/tool RCE report" in text
    assert "Approval / authorization analysis" in text


def test_cli_strict_returns_nonzero_for_needs_work(tmp_path: Path, capsys):
    repo = tmp_path / "repo"
    repo.mkdir()
    report = tmp_path / "finding.md"
    report.write_text(
        "# Plausible RCE\n\n"
        "Severity: Critical\n\n"
        "Attacker: remote unauthenticated\n\n"
        "PoC: curl /run\n",
        encoding="utf-8",
    )

    code = main([str(report), "--repo", str(repo), "--strict"])

    out = capsys.readouterr().out
    assert code == 2
    assert "Verdict: **NEEDS_WORK**" in out
    assert "## Evidence checklist" in out
    assert "`repro`" in out


def test_cli_profile_cve_request_emits_profile_check(tmp_path: Path, capsys):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "api.py").write_text("def handler():\n    pass\n", encoding="utf-8")
    report = tmp_path / "finding.md"
    report.write_text(
        "# Auth bypass\n\n"
        "Affected files: `api.py`\n\n"
        "Attacker: remote unauthenticated user.\n\n"
        "PoC: curl /api.\n",
        encoding="utf-8",
    )

    code = main([str(report), "--repo", str(repo), "--profile", "cve-request"])

    out = capsys.readouterr().out
    assert code == 0
    assert "Profile: `cve-request`" in out
    assert "Using `cve-request` validation profile." in out
    assert "`profile_cve_duplicate_review`" in out
