from __future__ import annotations

import argparse
from pathlib import Path
import sys

from .core import REPORT_TEMPLATES, VET_PROFILES, render_markdown, render_report_template, vet


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="verifymate",
        description="Repo-grounded verification assistant for vulnerability reports and AI-generated security findings.",
    )
    parser.add_argument("report", type=Path, nargs="?", help="Markdown vulnerability report to vet")
    parser.add_argument("--repo", type=Path, help="Repository checkout to compare against")
    parser.add_argument("--github", help="Optional GitHub owner/repo for simple duplicate search")
    parser.add_argument(
        "--profile",
        choices=VET_PROFILES,
        default="preflight",
        help="Validation profile: preflight, cve-request, github-pr, or internal-note.",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of Markdown")
    parser.add_argument("--out", type=Path, help="Write output to a file instead of stdout")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit 0 only for PASS/DUPLICATE_RISK; return 2 for INVALID/WEAK/NEEDS_WORK.",
    )
    parser.add_argument(
        "--template",
        choices=sorted(REPORT_TEMPLATES),
        help="Emit a starter vulnerability-report template instead of vetting a report.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.template:
        output = render_report_template(args.template)
        _emit(output.rstrip("\n"), args.out)
        return 0

    if args.repo is None:
        parser.error("--repo is required unless --template is used")
    if args.report is None:
        parser.error("report path is required unless --template is used")
    if not args.repo.exists():
        parser.error(f"--repo path does not exist: {args.repo}")
    if not args.report.exists():
        parser.error(f"report path does not exist: {args.report}")

    result = vet(args.repo, args.report, args.github, profile=args.profile)
    output = result.to_json() if args.json else render_markdown(result)
    _emit(output, args.out)
    if args.strict and result.verdict not in {"PASS", "DUPLICATE_RISK"}:
        return 2
    return 0 if result.verdict in {"PASS", "NEEDS_WORK", "DUPLICATE_RISK", "WEAK", "INVALID"} else 1


def _emit(output: str, out: Path | None) -> None:
    if out:
        out.write_text(output.rstrip("\n") + "\n", encoding="utf-8")
    else:
        print(output)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
