from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import json
import re
import subprocess
from typing import Iterable

DANGEROUS_TERMS = {
    "command execution": ["subprocess", "os.system", "exec(", "eval(", "shell=True", "child_process", "Runtime.getRuntime", "ProcessBuilder"],
    "file read/write": ["open(", "readFile", "writeFile", "send_file", "FileResponse", "Path("],
    "deserialization": ["pickle.load", "yaml.load", "loads(", "deserialize", "ObjectInputStream"],
    "ssrf/fetch": ["requests.get", "httpx.get", "fetch(", "axios", "urllib.request", "curl"],
    "plugin loading": ["importlib", "require(", "dlopen", "plugin", "extension", "load_module"],
}

AGENT_TERMS = [
    "agent", "tool", "tools", "mcp", "workflow", "executor", "runner", "sandbox",
    "workspace", "prompt", "llm", "approval", "terminal", "browser", "plugin", "function_call",
]

RCE_TERMS = ["rce", "remote code", "command execution", "arbitrary command", "code execution"]
FILE_TERMS = ["file read", "arbitrary file", "path traversal", "lfi", "directory traversal"]
SSRF_TERMS = ["ssrf", "server-side request", "metadata", "internal network"]
AUTH_TERMS = ["auth bypass", "authorization", "authentication", "idor", "privilege"]


@dataclass
class ParsedReport:
    text: str
    title: str | None = None
    severity: str | None = None
    files: list[str] = field(default_factory=list)
    symbols: list[str] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    has_repro: bool = False
    attacker_mentions: list[str] = field(default_factory=list)
    impact_terms: list[str] = field(default_factory=list)


@dataclass
class VetResult:
    verdict: str
    reason: str
    confirmed: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    questions: list[str] = field(default_factory=list)
    duplicate_matches: list[str] = field(default_factory=list)
    suggested_rewrite: str = ""
    parsed: dict = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(self.__dict__, indent=2, ensure_ascii=False)


def parse_report(path: Path) -> ParsedReport:
    text = path.read_text(encoding="utf-8", errors="replace")
    report = ParsedReport(text=text)

    title_match = re.search(r"^#\s+(.+)$", text, re.M)
    if title_match:
        report.title = title_match.group(1).strip()

    sev_match = re.search(r"(?im)^\s*(?:severity|impact)\s*[:\-]\s*(critical|high|medium|low|informational|info)\b", text)
    if sev_match:
        report.severity = sev_match.group(1).title()

    # Markdown code-ish paths plus explicit file labels.
    explicit_files = re.findall(r"(?im)^\s*(?:file|files|affected files?)\s*[:\-]\s*(.+)$", text)
    for chunk in explicit_files:
        report.files.extend(_extract_paths(chunk))
    report.files.extend(_extract_paths(text))
    report.files = sorted(set(_clean_file_ref(p) for p in report.files if _looks_like_path(p)))

    report.symbols = sorted(set(re.findall(r"`([A-Za-z_][\w:.]{2,})\s*(?:\(\))?`", text)))
    endpoint_candidates = re.findall(r"`?((?:(?:GET|POST|PUT|PATCH|DELETE)\s+)?/[A-Za-z0-9_./{}:\-]+)`?", text)
    report.endpoints = sorted(set(
        e for e in endpoint_candidates
        if not _looks_like_source_path(e.split(maxsplit=1)[-1])
        and not e.split(maxsplit=1)[-1].startswith(("//", "/tmp/", "/var/", "/Users/", "/home/"))
    ))

    report.has_repro = bool(re.search(r"(?i)\b(poc|proof|repro|curl|httpie|python - <<|steps to reproduce|minimal test)\b", text))
    report.attacker_mentions = sorted(set(re.findall(r"(?i)\b(unauthenticated|remote|authenticated|low-privilege|workspace member|malicious website|prompt injection|admin|operator|local user)\b", text)))
    lower = text.lower()
    report.impact_terms = [t for t in RCE_TERMS + FILE_TERMS + SSRF_TERMS + AUTH_TERMS if t in lower]
    return report


def _extract_paths(text: str) -> list[str]:
    candidates = re.findall(r"`([^`]+)`", text)
    candidates += re.findall(r"(?:^|\s)((?:[\w.-]+/)+[\w./{}:@+\-]+\.[A-Za-z0-9]+)", text)
    return candidates


def _clean_file_ref(ref: str) -> str:
    return ref.strip().strip(".,:;()[]{}'\"")


def _looks_like_path(ref: str) -> bool:
    if " " in ref and not ref.startswith("/"):
        return False
    if ref.startswith(("http://", "https://")):
        return False
    if ref.startswith("/"):
        return _looks_like_source_path(ref)
    return "/" in ref or _looks_like_source_path(ref)


def _looks_like_source_path(ref: str) -> bool:
    return bool(re.search(r"\.(py|js|ts|tsx|jsx|go|rs|java|rb|php|c|cc|cpp|h|hpp|yml|yaml|json|toml|md)$", ref))


def collect_repo_evidence(repo: Path, report: ParsedReport) -> tuple[list[str], list[str], bool, dict[str, list[str]]]:
    confirmed: list[str] = []
    missing: list[str] = []
    dangerous_hits: dict[str, list[str]] = {}

    all_text_files = list(_iter_text_files(repo))
    repo_blob = "\n".join(_safe_read(p) for p in all_text_files[:2000])
    repo_blob_lower = repo_blob.lower()

    agent_context = any(term in repo_blob_lower for term in AGENT_TERMS)
    if agent_context:
        confirmed.append("Agent/tool-related repository context detected.")

    for file_ref in report.files[:50]:
        path = (repo / file_ref).resolve()
        if path.exists() and _is_relative_to(path, repo.resolve()):
            confirmed.append(f"Referenced file exists: `{file_ref}`")
        else:
            missing.append(f"Referenced file not found on current checkout: `{file_ref}`")

    for symbol in report.symbols[:50]:
        if _search_literal(all_text_files, symbol):
            confirmed.append(f"Referenced symbol/string found: `{symbol}`")
        else:
            missing.append(f"Referenced symbol/string not found: `{symbol}`")

    for endpoint in report.endpoints[:30]:
        needle = endpoint.split(maxsplit=1)[-1]
        if _search_literal(all_text_files, needle):
            confirmed.append(f"Referenced endpoint/path string found: `{endpoint}`")
        else:
            missing.append(f"Referenced endpoint/path string not found: `{endpoint}`")

    for category, terms in DANGEROUS_TERMS.items():
        hits = [term for term in terms if term.lower() in repo_blob_lower]
        if hits:
            dangerous_hits[category] = hits[:8]
            confirmed.append(f"Dangerous-capability terms present ({category}): {', '.join(hits[:5])}")

    if report.has_repro:
        confirmed.append("Report appears to include a PoC/repro section or command.")
    else:
        missing.append("No obvious PoC/repro evidence found in report text.")

    if report.attacker_mentions:
        confirmed.append("Attacker model terms present: " + ", ".join(report.attacker_mentions))
    else:
        missing.append("No clear attacker position found, e.g. unauthenticated, low-privilege, malicious website, prompt injection.")

    return confirmed, missing, agent_context, dangerous_hits


def generate_questions(report: ParsedReport, agent_context: bool, dangerous_hits: dict[str, list[str]]) -> list[str]:
    lower = report.text.lower()
    questions: list[str] = [
        "What exact attacker-controlled input starts the exploit chain?",
        "What trusted component processes that input?",
        "What security boundary is crossed?",
        "What concrete asset/user is harmed?",
    ]

    if agent_context:
        questions += [
            "Is this API intended for agent/tool use, and if so what unauthorized boundary is bypassed?",
            "Can an untrusted remote caller, malicious website, prompt injection, or another workspace invoke it without approval?",
        ]

    if any(term in lower for term in RCE_TERMS) or "command execution" in dangerous_hits:
        questions += [
            "Who can reach the command/code execution sink in default configuration?",
            "Is there authentication, authorization, user approval, or sandboxing before execution?",
            "What safe command proves impact, and is cleanup documented?",
        ]
    if any(term in lower for term in FILE_TERMS) or "file read/write" in dangerous_hits:
        questions += [
            "Is file access intentionally workspace-scoped, and can the report prove escape via traversal or symlink?",
            "Can sensitive data be exfiltrated to an attacker-controlled channel?",
        ]
    if any(term in lower for term in SSRF_TERMS) or "ssrf/fetch" in dangerous_hits:
        questions += [
            "Can attacker-controlled URLs reach private IPs, redirects, DNS rebinding targets, or cloud metadata?",
        ]
    if any(term in lower for term in AUTH_TERMS):
        questions += [
            "What privilege does the attacker start with and what privilege do they gain?",
        ]

    questions.append("What would the maintainer say to dismiss this as intended, admin-only, duplicate, or out of scope?")
    return _dedupe(questions)[:10]


def decide_verdict(report: ParsedReport, missing: list[str], agent_context: bool) -> tuple[str, str, str]:
    missing_files = [m for m in missing if "file not found" in m]
    missing_symbols = [m for m in missing if "symbol/string not found" in m or "endpoint/path string not found" in m]
    no_repro = any("No obvious PoC" in m for m in missing)
    no_attacker = any("No clear attacker" in m for m in missing)
    lower = report.text.lower()
    claimed_critical_rce = (report.severity or "").lower() == "critical" or "critical" in lower and any(t in lower for t in RCE_TERMS)

    if missing_files or (missing_symbols and len(missing_symbols) >= 3):
        return "INVALID", "Important referenced repo evidence is missing on current checkout.", "Do not file yet. First correct file/symbol/endpoint references against current HEAD."
    if agent_context and claimed_critical_rce and ("boundary" not in lower and "bypass" not in lower and "unauth" not in lower):
        return "WEAK", "This appears to involve agent/tool functionality, but the report does not prove unauthorized boundary crossing.", "Rewrite as a potential boundary issue, then prove unauthorized invocation, approval bypass, sandbox escape, cross-user impact, or secret exposure."
    if no_attacker:
        return "WEAK", "The report does not define who the attacker is or how they reach the issue.", "Add a precise attacker model before claiming severity."
    if no_repro:
        return "NEEDS_WORK", "The claim may be plausible, but it lacks a minimal PoC/repro.", "Add a safe repro against current HEAD and document expected vs actual result."
    if claimed_critical_rce and "auth" not in lower and "unauth" not in lower and "approval" not in lower:
        return "NEEDS_WORK", "Critical RCE is claimed without enough auth/approval/default-exposure analysis.", "Add default exposure, auth, and approval analysis or downgrade severity."
    return "PASS", "The report has repo grounding, attacker framing, and repro indicators. Human review may still ask follow-up questions.", "File the report, but include the maintainer-question answers inline."


def duplicate_search(owner_repo: str | None, report: ParsedReport) -> list[str]:
    if not owner_repo:
        return []
    if not _has_command("gh"):
        return ["GitHub duplicate check skipped: `gh` CLI not available."]
    terms = []
    terms.extend(report.endpoints[:2])
    terms.extend(report.symbols[:2])
    terms.extend(report.impact_terms[:2])
    terms = [t.strip("` ") for t in terms if len(t.strip()) >= 3][:4]
    if not terms:
        return ["GitHub duplicate check skipped: no good search terms extracted."]
    matches: list[str] = []
    for term in terms:
        try:
            proc = subprocess.run(
                ["gh", "search", "issues", term, "--repo", owner_repo, "--include-prs", "--limit", "5", "--json", "number,title,state,url"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=20,
            )
        except Exception as exc:  # pragma: no cover
            matches.append(f"GitHub duplicate search failed for `{term}`: {exc}")
            continue
        if proc.returncode != 0:
            matches.append(f"GitHub duplicate search failed for `{term}`: {proc.stderr.strip()[:160]}")
            continue
        try:
            rows = json.loads(proc.stdout or "[]")
        except json.JSONDecodeError:
            rows = []
        for row in rows[:3]:
            matches.append(f"Possible related item for `{term}`: #{row['number']} {row['title']} ({row['state']}) {row['url']}")
    return _dedupe(matches) or ["No obvious GitHub issue/PR duplicates found from simple search terms."]


def vet(repo: Path, report_path: Path, owner_repo: str | None = None) -> VetResult:
    report = parse_report(report_path)
    confirmed, missing, agent_context, dangerous_hits = collect_repo_evidence(repo, report)
    questions = generate_questions(report, agent_context, dangerous_hits)
    duplicates = duplicate_search(owner_repo, report)
    verdict, reason, rewrite = decide_verdict(report, missing, agent_context)
    if duplicates and not duplicates[0].startswith("No obvious") and not duplicates[0].startswith("GitHub duplicate check skipped") and verdict == "PASS":
        verdict = "DUPLICATE_RISK"
        reason = "The finding looks grounded, but similar public GitHub items may already exist."
    return VetResult(
        verdict=verdict,
        reason=reason,
        confirmed=_dedupe(confirmed),
        missing=_dedupe(missing),
        questions=questions,
        duplicate_matches=duplicates,
        suggested_rewrite=rewrite,
        parsed={
            "title": report.title,
            "severity": report.severity,
            "files": report.files,
            "symbols": report.symbols,
            "endpoints": report.endpoints,
            "has_repro": report.has_repro,
            "attacker_mentions": report.attacker_mentions,
            "impact_terms": report.impact_terms,
        },
    )


def render_markdown(result: VetResult) -> str:
    lines = [
        "# Finding Vetter Result",
        "",
        f"Verdict: **{result.verdict}**",
        "",
        "## One-line reason",
        "",
        result.reason,
        "",
        "## Confirmed from repo/report",
        "",
    ]
    lines += _bullet_list(result.confirmed, empty="No strong confirming evidence found.")
    lines += ["", "## Missing or weak evidence", ""]
    lines += _bullet_list(result.missing, empty="No obvious blockers found by the lightweight checks.")
    lines += ["", "## Maintainer will ask", ""]
    lines += [f"{i}. {q}" for i, q in enumerate(result.questions, 1)]
    if result.duplicate_matches:
        lines += ["", "## Duplicate risk", ""]
        lines += _bullet_list(result.duplicate_matches)
    lines += ["", "## Suggested next step", "", result.suggested_rewrite, ""]
    return "\n".join(lines)


def _bullet_list(items: Iterable[str], empty: str = "None.") -> list[str]:
    items = list(items)
    if not items:
        return [f"- {empty}"]
    return [f"- {item}" for item in items]


def _iter_text_files(repo: Path) -> Iterable[Path]:
    skip_dirs = {".git", "node_modules", ".venv", "venv", "dist", "build", "target", "__pycache__"}
    for path in repo.rglob("*"):
        if any(part in skip_dirs for part in path.parts):
            continue
        if path.is_file() and path.stat().st_size < 1_000_000:
            yield path


def _safe_read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def _search_literal(files: Iterable[Path], needle: str) -> bool:
    if not needle:
        return False
    for path in files:
        if needle in _safe_read(path):
            return True
    return False


def _dedupe(items: Iterable[str]) -> list[str]:
    seen = set()
    out = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _has_command(cmd: str) -> bool:
    return subprocess.run(["/usr/bin/env", "sh", "-c", f"command -v {cmd} >/dev/null 2>&1"], timeout=5).returncode == 0


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False
