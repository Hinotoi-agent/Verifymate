from __future__ import annotations

import argparse
from pathlib import Path
import sys

from .core import render_markdown, vet


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="finding-vetter",
        description="Lightweight repo-grounded reviewer for AI-generated vulnerability reports.",
    )
    parser.add_argument("report", type=Path, help="Markdown vulnerability report to vet")
    parser.add_argument("--repo", type=Path, required=True, help="Repository checkout to compare against")
    parser.add_argument("--github", help="Optional GitHub owner/repo for simple duplicate search")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of Markdown")
    parser.add_argument("--out", type=Path, help="Write output to a file instead of stdout")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.repo.exists():
        parser.error(f"--repo path does not exist: {args.repo}")
    if not args.report.exists():
        parser.error(f"report path does not exist: {args.report}")

    result = vet(args.repo, args.report, args.github)
    output = result.to_json() if args.json else render_markdown(result)
    if args.out:
        args.out.write_text(output + "\n", encoding="utf-8")
    else:
        print(output)
    return 0 if result.verdict in {"PASS", "NEEDS_WORK", "DUPLICATE_RISK", "WEAK", "INVALID"} else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
