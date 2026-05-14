from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import json
import re
import subprocess
from typing import Iterable

DANGEROUS_TERMS = {
    "command execution": [
        "subprocess",
        "os.system",
        "exec(",
        "eval(",
        "shell=True",
        "child_process",
        "Runtime.getRuntime",
        "ProcessBuilder",
    ],
    "file read/write": ["open(", "readFile", "writeFile", "send_file", "FileResponse", "Path("],
    "deserialization": ["pickle.load", "yaml.load", "loads(", "deserialize", "ObjectInputStream"],
    "ssrf/fetch": ["requests.get", "httpx.get", "fetch(", "axios", "urllib.request", "curl"],
    "plugin loading": ["importlib", "require(", "dlopen", "plugin", "extension", "load_module"],
}

AGENT_TERMS = [
    "agent",
    "tool",
    "tools",
    "mcp",
    "workflow",
    "executor",
    "runner",
    "sandbox",
    "workspace",
    "prompt",
    "llm",
    "approval",
    "terminal",
    "browser",
    "plugin",
    "function_call",
]

RCE_TERMS = ["rce", "remote code", "command execution", "arbitrary command", "code execution"]
FILE_TERMS = ["file read", "arbitrary file", "path traversal", "lfi", "directory traversal"]
SSRF_TERMS = ["ssrf", "server-side request", "metadata", "internal network"]
AUTH_TERMS = ["auth bypass", "authorization", "authentication", "idor", "privilege"]
VET_PROFILES = ("preflight", "cve-request", "github-pr", "internal-note")

OWASP_TOP_10_RULES: list[tuple[str, tuple[str, ...]]] = [
    (
        "A01:2021-Broken Access Control",
        (
            "access control",
            "auth bypass",
            "authorization",
            "unauthenticated",
            "unauthorized",
            "bypass",
            "privilege",
            "idor",
            "cross-user",
            "admin",
        ),
    ),
    (
        "A02:2021-Cryptographic Failures",
        ("secret", "token", "credential", "password", "api key", "plaintext", "encrypt", "tls"),
    ),
    (
        "A03:2021-Injection",
        (
            "injection",
            "command execution",
            "code execution",
            "rce",
            "subprocess",
            "shell=true",
            "sql",
            "xss",
            "template injection",
        ),
    ),
    (
        "A04:2021-Insecure Design",
        ("insecure design", "boundary", "threat model", "approval", "sandbox", "default"),
    ),
    (
        "A05:2021-Security Misconfiguration",
        ("misconfiguration", "debug", "0.0.0.0", "cors", "default configuration"),
    ),
    (
        "A06:2021-Vulnerable and Outdated Components",
        ("dependency", "outdated", "cve", "vulnerable component"),
    ),
    (
        "A07:2021-Identification and Authentication Failures",
        ("authentication", "login", "session", "jwt", "password reset"),
    ),
    (
        "A08:2021-Software and Data Integrity Failures",
        ("plugin", "extension", "supply chain", "unsigned", "deserialization", "pickle"),
    ),
    (
        "A09:2021-Security Logging and Monitoring Failures",
        ("logging", "monitoring", "audit", "alert"),
    ),
    (
        "A10:2021-Server-Side Request Forgery",
        ("ssrf", "server-side request", "metadata", "internal network", "redirect"),
    ),
]

OWASP_LLM_TOP_10_RULES: list[tuple[str, tuple[str, ...]]] = [
    ("LLM01:2025 Prompt Injection", ("prompt injection", "prompt", "system prompt")),
    (
        "LLM02:2025 Sensitive Information Disclosure",
        ("secret", "token", "credential", "password", "api key", "system prompt leakage"),
    ),
    ("LLM03:2025 Supply Chain", ("plugin", "extension", "model", "dependency", "supply chain")),
    ("LLM04:2025 Data and Model Poisoning", ("poison", "training data", "fine-tune", "dataset")),
    (
        "LLM05:2025 Improper Output Handling",
        ("output handling", "eval(", "exec(", "template", "sql", "command execution"),
    ),
    (
        "LLM06:2025 Excessive Agency",
        ("agent", "tool", "approval", "function_call", "subprocess", "shell=true", "executor"),
    ),
    ("LLM07:2025 System Prompt Leakage", ("system prompt", "prompt leakage", "leak prompt")),
    (
        "LLM08:2025 Vector and Embedding Weaknesses",
        ("embedding", "vector", "rag", "retrieval", "index poisoning"),
    ),
    ("LLM09:2025 Misinformation", ("misinformation", "hallucination", "incorrect output")),
    (
        "LLM10:2025 Unbounded Consumption",
        ("unbounded", "resource exhaustion", "denial of service", "dos"),
    ),
]

REPORT_TEMPLATES: dict[str, str] = {
    "general": """# Vulnerability report

Severity: <Critical|High|Medium|Low>

## Summary
Describe the issue in one paragraph.

## Affected / tested version
- Repository commit or release:
- Default configuration assumptions:

## Attack surface
Who can reach the vulnerable path and under what privileges?

## Root cause
Name the vulnerable file/symbol and explain why attacker input is trusted.

## Reproduction
Use a safe, minimal PoC. Include expected result, actual result, and cleanup.

## Impact
Describe the concrete asset, user, or security boundary affected.

## Fix guidance
Describe the smallest mitigation or validation rule that closes the issue.
""",
    "critical-rce": """# Critical RCE report

Severity: Critical

## Summary
Explain the remote code execution claim in one paragraph.

## Affected / tested version
- Repository commit or release:
- Default configuration assumptions:
- Environment required to reproduce:

## Attack surface
Describe the remote entrypoint, auth/approval state, and attacker-controlled input.

## Source-to-sink root cause
Trace attacker input from the entrypoint to the execution sink with file/symbol names.

## Exploit chain
List the steps that transform attacker input into command/code execution.

## Safe PoC
Provide a non-destructive proof, expected side effect, observed result, and cleanup.

## Impact
Explain what code runs, under which OS/application identity, and what data or host boundary is exposed.

## Fix guidance
Describe the validation, authorization, sandboxing, or shell-avoidance change needed.
""",
    "agent-rce": """# Agent/tool RCE report

Severity: Critical

## Summary
Explain why this is more than intended agent/tool functionality.

## Affected / tested version
- Repository commit or release:
- Default configuration assumptions:

## Agent/tool boundary
Describe the agent API, tool, workflow, MCP server, browser bridge, or executor involved.

## Approval / authorization analysis
State who can trigger execution and whether auth, user approval, sandboxing, or workspace isolation is bypassed.

## Source-to-sink root cause
Trace attacker-controlled input from prompt/API/website/workspace content to the execution sink.

## Safe PoC
Use a harmless side effect such as writing a temp marker. Include expected result and cleanup.

## Impact
Describe host command execution, cross-user effect, secret exposure, or sandbox escape.

## Fix guidance
Describe how to restore the intended boundary: approval gating, origin/auth checks, sandboxing, allowlists, or path containment.
""",
}


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
    has_affected_or_tested_version: bool = False
    has_attack_surface: bool = False
    has_root_cause: bool = False
    has_exploit_chain: bool = False
    has_safe_side_effect: bool = False
    has_fix_guidance: bool = False


@dataclass
class VetResult:
    verdict: str
    reason: str
    checks: list[dict[str, str]] = field(default_factory=list)
    confirmed: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    evidence_locations: list[dict[str, str]] = field(default_factory=list)
    questions: list[str] = field(default_factory=list)
    duplicate_matches: list[str] = field(default_factory=list)
    suggested_rewrite: str = ""
    parsed: dict = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(self.__dict__, indent=2, ensure_ascii=False)


def render_report_template(kind: str = "general") -> str:
    """Return a starter report template for a supported finding type."""
    try:
        return REPORT_TEMPLATES[kind].strip() + "\n"
    except KeyError as exc:
        allowed = ", ".join(sorted(REPORT_TEMPLATES))
        raise ValueError(f"unknown template kind {kind!r}; choose one of: {allowed}") from exc


def parse_report(path: Path) -> ParsedReport:
    text = path.read_text(encoding="utf-8", errors="replace")
    report = ParsedReport(text=text)

    title_match = re.search(r"^#\s+(.+)$", text, re.M)
    if title_match:
        report.title = title_match.group(1).strip()

    sev_match = re.search(
        r"(?im)^\s*(?:severity|impact)\s*[:\-]\s*(critical|high|medium|low|informational|info)\b",
        text,
    )
    if sev_match:
        report.severity = sev_match.group(1).title()

    # Markdown code-ish paths plus explicit file labels.
    explicit_files = re.findall(r"(?im)^\s*(?:file|files|affected files?)\s*[:\-]\s*(.+)$", text)
    for chunk in explicit_files:
        report.files.extend(_extract_paths(chunk))
    report.files.extend(_extract_paths(text))
    report.files = sorted(set(_clean_file_ref(p) for p in report.files if _looks_like_path(p)))

    report.symbols = sorted(
        set(
            symbol
            for symbol in re.findall(r"`([A-Za-z_][\w:.]{2,})\s*(?:\(\))?`", text)
            if not _looks_like_path(symbol)
        )
    )
    endpoint_candidates = re.findall(
        r"`?((?:(?:GET|POST|PUT|PATCH|DELETE)\s+)?/[A-Za-z0-9_./{}:\-]+)`?", text
    )
    report.endpoints = sorted(
        set(
            e
            for e in endpoint_candidates
            if not _looks_like_source_path(e.split(maxsplit=1)[-1])
            and not e.split(maxsplit=1)[-1].startswith(
                ("//", "/tmp/", "/var/", "/Users/", "/home/")
            )
        )
    )

    report.has_repro = bool(
        re.search(
            r"(?i)\b(poc|proof|repro|curl|httpie|python - <<|steps to reproduce|minimal test)\b",
            text,
        )
    )
    report.attacker_mentions = sorted(
        set(
            re.findall(
                r"(?i)\b(unauthenticated|remote|authenticated|low-privilege|workspace member|malicious website|prompt injection|admin|operator|local user)\b",
                text,
            )
        )
    )
    lower = text.lower()
    report.impact_terms = [
        t for t in RCE_TERMS + FILE_TERMS + SSRF_TERMS + AUTH_TERMS if t in lower
    ]
    report.has_affected_or_tested_version = bool(
        re.search(
            r"(?im)^\s*(?:affected(?!\s+files?)|tested on|confirmed against|version|commit|current head|default configuration)\b",
            text,
        )
    )
    report.has_attack_surface = bool(
        re.search(
            r"(?i)\b(attack surface|entrypoint|entry point|reachable|default configuration|port \d+|victim action)\b",
            text,
        )
    )
    report.has_root_cause = bool(
        re.search(
            r"(?i)\b(root cause|bug is|vulnerability is|without checking|without auth|bounds check|validation|sanitize|source-to-sink|copies attacker-controlled)\b",
            text,
        )
    )
    report.has_exploit_chain = bool(
        re.search(
            r"(?i)\b(exploit chain|trigger|primitive|source[- ]to[- ]sink|->|leads to|reaches the sink|flows? to|reaches?)\b",
            text,
        )
    )
    report.has_safe_side_effect = bool(
        re.search(
            r"(?i)\b(expected result|actual result|safe side effect|created and then removed|cleanup|rm /tmp|test -f|id > /tmp|touch /tmp)\b",
            text,
        )
    )
    report.has_fix_guidance = bool(
        re.search(
            r"(?i)\b(fix|patch|mitigation|remediation|allowlist|denylist|bounds check|validate|sanitize|shell=false|authentication)\b",
            text,
        )
    )
    return report


def _extract_paths(text: str) -> list[str]:
    candidates = re.findall(r"`([^`]+)`", text)
    candidates += re.findall(r"(?:^|\s)((?:[\w.-]+/)+[\w./{}:@+\-]+\.[A-Za-z0-9]+)", text)
    return candidates


def _clean_file_ref(ref: str) -> str:
    cleaned = ref.strip().strip(".,:;()[]{}'\"")
    cleaned = re.sub(r"#L\d+(?:-L\d+)?$", "", cleaned)
    cleaned = re.sub(r":\d+(?::\d+)?$", "", cleaned)
    return cleaned


def _looks_like_path(ref: str) -> bool:
    if " " in ref and not ref.startswith("/"):
        return False
    if ref.startswith(("http://", "https://")):
        return False
    if ref.startswith("/"):
        return _looks_like_source_path(ref)
    return "/" in ref or _looks_like_source_path(ref)


def _looks_like_source_path(ref: str) -> bool:
    return bool(
        re.search(
            r"\.(py|js|ts|tsx|jsx|go|rs|java|rb|php|c|cc|cpp|h|hpp|yml|yaml|json|toml|md)$", ref
        )
    )


def collect_repo_evidence(
    repo: Path, report: ParsedReport
) -> tuple[list[str], list[str], list[dict[str, str]], bool, dict[str, list[str]]]:
    confirmed: list[str] = []
    missing: list[str] = []
    evidence_locations: list[dict[str, str]] = []
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
            evidence_locations.append(
                _evidence_location("file", file_ref, file_ref, 1, "Referenced file exists.")
            )
        else:
            missing.append(f"Referenced file not found on current checkout: `{file_ref}`")

    for symbol in report.symbols[:50]:
        hit = _find_literal_location(all_text_files, symbol, repo)
        if hit:
            confirmed.append(f"Referenced symbol/string found: `{symbol}`")
            evidence_locations.append(_evidence_location("symbol", symbol, *hit))
        else:
            missing.append(f"Referenced symbol/string not found: `{symbol}`")

    for endpoint in report.endpoints[:30]:
        needle = endpoint.split(maxsplit=1)[-1]
        hit = _find_literal_location(all_text_files, needle, repo)
        if hit:
            confirmed.append(f"Referenced endpoint/path string found: `{endpoint}`")
            evidence_locations.append(_evidence_location("endpoint", endpoint, *hit))
        else:
            missing.append(f"Referenced endpoint/path string not found: `{endpoint}`")

    for category, terms in DANGEROUS_TERMS.items():
        hits = [term for term in terms if term.lower() in repo_blob_lower]
        if hits:
            dangerous_hits[category] = hits[:8]
            confirmed.append(
                f"Dangerous-capability terms present ({category}): {', '.join(hits[:5])}"
            )
            for term in hits[:3]:
                hit = _find_literal_location(all_text_files, term, repo, case_sensitive=False)
                if hit:
                    evidence_locations.append(_evidence_location(category, term, *hit))

    if report.has_repro:
        confirmed.append("Report appears to include a PoC/repro section or command.")
    else:
        missing.append("No obvious PoC/repro evidence found in report text.")

    if report.attacker_mentions:
        confirmed.append("Attacker model terms present: " + ", ".join(report.attacker_mentions))
    else:
        missing.append(
            "No clear attacker position found, e.g. unauthenticated, low-privilege, malicious website, prompt injection."
        )

    if _claims_high_impact_rce(report):
        _add_madbugs_style_evidence(report, confirmed, missing)

    return confirmed, missing, _dedupe_locations(evidence_locations), agent_context, dangerous_hits


def _claims_high_impact_rce(report: ParsedReport) -> bool:
    lower = report.text.lower()
    return ((report.severity or "").lower() in {"critical", "high"} or "critical" in lower) and any(
        term in lower for term in RCE_TERMS
    )


def _add_madbugs_style_evidence(
    report: ParsedReport, confirmed: list[str], missing: list[str]
) -> None:
    checks = [
        (
            report.has_affected_or_tested_version,
            "MADBugs-style affected/tested version or commit context is present.",
            "Critical RCE needs affected/tested version or current-HEAD/default-config context.",
        ),
        (
            report.has_attack_surface,
            "Attack surface or reachable entrypoint context is present.",
            "Critical RCE needs attack-surface/default-reachability context.",
        ),
        (
            report.has_root_cause,
            "Root-cause explanation is present.",
            "Critical RCE needs root-cause/source-to-sink explanation, not only a dangerous sink.",
        ),
        (
            report.has_exploit_chain,
            "Exploit chain or trigger path is present.",
            "Critical RCE needs a trigger/exploit chain from attacker input to impact.",
        ),
        (
            report.has_safe_side_effect,
            "PoC describes an expected result, cleanup, or safe side effect.",
            "Critical RCE PoC should use a safe side effect and state expected result/cleanup.",
        ),
        (
            report.has_fix_guidance,
            "Fix, patch, or mitigation guidance is present.",
            "Critical RCE report should include concise fix/mitigation guidance.",
        ),
    ]
    for ok, good, bad in checks:
        if ok:
            confirmed.append(good)
        else:
            missing.append(bad)


def generate_questions(
    report: ParsedReport, agent_context: bool, dangerous_hits: dict[str, list[str]]
) -> list[str]:
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
            "What affected/tested version or commit proves this is current?",
            "What is the root-cause source-to-sink chain from attacker input to execution?",
            "What safe side effect proves impact, and is cleanup documented?",
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

    questions.append(
        "What would the maintainer say to dismiss this as intended, admin-only, duplicate, or out of scope?"
    )
    return _dedupe(questions)[:10]


def decide_verdict(
    report: ParsedReport, missing: list[str], agent_context: bool, profile: str = "preflight"
) -> tuple[str, str, str]:
    missing_files = [m for m in missing if "file not found" in m]
    missing_symbols = [
        m
        for m in missing
        if "symbol/string not found" in m or "endpoint/path string not found" in m
    ]
    no_repro = any("No obvious PoC" in m for m in missing)
    no_attacker = any("No clear attacker" in m for m in missing)
    missing_madbugs_rce_context = [
        m for m in missing if m.startswith("Critical RCE needs") or m.startswith("Critical RCE PoC")
    ]
    lower = report.text.lower()
    claimed_critical_rce = (
        (report.severity or "").lower() == "critical"
        or "critical" in lower
        and any(t in lower for t in RCE_TERMS)
    )

    if missing_files or (missing_symbols and len(missing_symbols) >= 3):
        return (
            "INVALID",
            "Important referenced repo evidence is missing on current checkout.",
            "Do not file yet. First correct file/symbol/endpoint references against current HEAD.",
        )
    if (
        agent_context
        and claimed_critical_rce
        and ("boundary" not in lower and "bypass" not in lower and "unauth" not in lower)
    ):
        return (
            "WEAK",
            "This appears to involve agent/tool functionality, but the report does not prove unauthorized boundary crossing.",
            "Rewrite as a potential boundary issue, then prove unauthorized invocation, approval bypass, sandbox escape, cross-user impact, or secret exposure.",
        )
    if no_attacker:
        return (
            "WEAK",
            "The report does not define who the attacker is or how they reach the issue.",
            "Add a precise attacker model before claiming severity.",
        )
    if claimed_critical_rce and missing_madbugs_rce_context:
        return (
            "NEEDS_WORK",
            "Critical RCE is plausible, but missing MADBugs-style context: affected/tested version, root cause, exploit chain, safe PoC evidence, or fix guidance.",
            "Add the affected/tested version, default attack surface, source-to-sink root cause, safe side-effect PoC with cleanup, and concise fix guidance.",
        )
    if no_repro and profile == "internal-note":
        return (
            "NEEDS_WORK",
            "Internal-note profile allows rough triage, but this note is not ready to file without a minimal repro.",
            "Keep as an internal note until a safe current-HEAD repro or code-path proof is added.",
        )
    if no_repro:
        return (
            "NEEDS_WORK",
            "The claim may be plausible, but it lacks a minimal PoC/repro.",
            "Add a safe repro against current HEAD and document expected vs actual result.",
        )
    if (
        claimed_critical_rce
        and "auth" not in lower
        and "unauth" not in lower
        and "approval" not in lower
    ):
        return (
            "NEEDS_WORK",
            "Critical RCE is claimed without enough auth/approval/default-exposure analysis.",
            "Add default exposure, auth, and approval analysis or downgrade severity.",
        )
    return (
        "PASS",
        "The report has repo grounding, attacker framing, and repro indicators. Human review may still ask follow-up questions.",
        "File the report, but include the maintainer-question answers inline.",
    )


def build_evidence_checklist(
    report: ParsedReport,
    missing: list[str],
    agent_context: bool,
    evidence_locations: list[dict[str, str]] | None = None,
    dangerous_hits: dict[str, list[str]] | None = None,
    profile: str = "preflight",
    duplicate_search_requested: bool = False,
) -> list[dict[str, str]]:
    """Return deterministic checker gates for UI and JSON consumers.

    The prose `confirmed` / `missing` lists are useful for humans, but they are hard to
    scan and hard to gate in automation. These checks keep Verifymate as a checker:
    each row has a stable id, category, pass/warn/fail status, blocking flag, detail,
    and line-backed evidence summary where available.
    """
    evidence_locations = evidence_locations or []
    dangerous_hits = dangerous_hits or {}
    missing_files = [m for m in missing if "file not found" in m]
    missing_repo_refs = [
        m
        for m in missing
        if "symbol/string not found" in m or "endpoint/path string not found" in m
    ]
    repo_grounding = _repo_grounding_check(missing_files, missing_repo_refs, evidence_locations)
    attacker_path = _attacker_path_check(report, dangerous_hits)
    checks: list[dict[str, str]] = [
        repo_grounding,
        attacker_path,
        _owasp_rationalization_check(
            report, dangerous_hits, OWASP_TOP_10_RULES, "owasp_top_10", "owasp"
        ),
        _owasp_rationalization_check(
            report,
            dangerous_hits,
            OWASP_LLM_TOP_10_RULES,
            "owasp_llm_top_10",
            "owasp_llm",
        ),
        _check(
            "attacker_model",
            "attacker_path",
            "pass" if report.attacker_mentions else "fail",
            "Attacker position terms found: " + ", ".join(report.attacker_mentions)
            if report.attacker_mentions
            else "Report should state who can trigger the issue and with what privileges.",
            blocking=True,
        ),
        _check(
            "repro",
            "proof",
            "pass" if report.has_repro else "fail",
            "PoC/repro indicator found."
            if report.has_repro
            else "Report should include a safe minimal reproduction or proof command.",
            blocking=True,
        ),
        _check(
            "impact",
            "impact",
            "pass" if report.impact_terms else "warn",
            "Impact terms found: " + ", ".join(report.impact_terms)
            if report.impact_terms
            else "Impact should name the affected asset, boundary, or capability.",
            blocking=False,
        ),
    ]

    # Compatibility row for consumers that already key on repo_refs.
    checks.append(
        _check(
            "repo_refs",
            "repo_grounding",
            repo_grounding["status"],
            repo_grounding["detail"],
            blocking=True,
            evidence=repo_grounding["evidence"],
        )
    )

    if agent_context:
        lower = report.text.lower()
        has_boundary = any(
            term in lower
            for term in (
                "boundary",
                "bypass",
                "unauth",
                "approval",
                "sandbox",
                "cross-user",
                "workspace",
                "secret",
            )
        )
        checks.append(
            _check(
                "agent_boundary",
                "boundary",
                "pass" if has_boundary else "warn",
                "Agent/tool boundary language is present."
                if has_boundary
                else "Agent/tool repos need an explicit unauthorized invocation, approval-bypass, sandbox-escape, cross-user, or secret-exposure boundary.",
                blocking=False,
            )
        )

    if _claims_high_impact_rce(report):
        checks.extend(
            [
                _boolean_check(
                    "affected_version",
                    "repo_grounding",
                    report.has_affected_or_tested_version,
                    "Affected/tested version or commit context is present.",
                    "Add affected/tested version, commit, or current-HEAD/default-config context.",
                ),
                _boolean_check(
                    "attack_surface",
                    "attacker_path",
                    report.has_attack_surface,
                    "Attack surface or reachable entrypoint context is present.",
                    "Add default reachability, entrypoint, auth, and exposure context.",
                ),
                _boolean_check(
                    "root_cause",
                    "attacker_path",
                    report.has_root_cause,
                    "Root-cause/source-to-sink explanation is present.",
                    "Trace attacker input from entrypoint to vulnerable sink.",
                ),
                _boolean_check(
                    "exploit_chain",
                    "attacker_path",
                    report.has_exploit_chain,
                    "Exploit chain or trigger path is present.",
                    "List the steps from attacker input to impact.",
                ),
                _boolean_check(
                    "safe_poc",
                    "proof",
                    report.has_safe_side_effect,
                    "PoC describes expected result, cleanup, or safe side effect.",
                    "Use a harmless side effect and document expected result plus cleanup.",
                ),
                _boolean_check(
                    "fix_guidance",
                    "maintainer_readiness",
                    report.has_fix_guidance,
                    "Fix, patch, or mitigation guidance is present.",
                    "Add concise mitigation guidance for the maintainer.",
                ),
            ]
        )

    checks.extend(_profile_checks(report, profile, duplicate_search_requested))
    checks = _apply_profile_blocking(checks, profile)
    return checks


def _profile_checks(
    report: ParsedReport, profile: str, duplicate_search_requested: bool
) -> list[dict[str, str]]:
    """Return deterministic profile-specific readiness rows.

    Profiles tune disclosure-readiness expectations without changing Verifymate into
    an exploit generator or static analyzer. They are intentionally based on report
    evidence and CLI options only.
    """
    if profile not in VET_PROFILES:
        allowed = ", ".join(VET_PROFILES)
        raise ValueError(f"unknown profile {profile!r}; choose one of: {allowed}")

    checks: list[dict[str, str]] = [
        _check(
            "profile",
            "profile",
            "pass",
            f"Using `{profile}` validation profile.",
            blocking=False,
        )
    ]
    if profile == "preflight":
        return checks

    if profile == "cve-request":
        checks.extend(
            [
                _boolean_check(
                    "profile_cve_affected_version",
                    "profile",
                    report.has_affected_or_tested_version,
                    "CVE request includes affected/tested version context.",
                    "CVE requests should state affected versions, tested commit, or current-HEAD context.",
                ),
                _boolean_check(
                    "profile_cve_safe_repro",
                    "profile",
                    report.has_repro and report.has_safe_side_effect,
                    "CVE request includes a safe repro with expected result or cleanup context.",
                    "CVE requests should include a safe repro or code-path proof with expected result and cleanup.",
                ),
                _boolean_check(
                    "profile_cve_fix_guidance",
                    "profile",
                    report.has_fix_guidance,
                    "CVE request includes concise mitigation guidance.",
                    "CVE requests should include concise fix or mitigation guidance.",
                ),
                _boolean_check(
                    "profile_cve_duplicate_review",
                    "profile",
                    duplicate_search_requested or _has_duplicate_review_evidence(report.text),
                    "CVE request includes duplicate/prior-art review evidence or `--github` search was requested.",
                    "CVE requests should include duplicate/prior-art review evidence or be run with `--github owner/repo`.",
                ),
            ]
        )
    elif profile == "github-pr":
        checks.extend(
            [
                _boolean_check(
                    "profile_pr_files",
                    "profile",
                    bool(report.files),
                    "GitHub PR profile has affected file references.",
                    "GitHub PR profile should name the files or components the patch changes.",
                ),
                _boolean_check(
                    "profile_pr_fix_guidance",
                    "profile",
                    report.has_fix_guidance,
                    "GitHub PR profile includes patch/fix direction.",
                    "GitHub PR profile should explain the patch or smallest fix direction.",
                ),
            ]
        )
    elif profile == "internal-note":
        checks.append(
            _check(
                "profile_internal_note",
                "profile",
                "warn" if not report.has_repro else "pass",
                "Internal-note profile is allowed to capture rough triage, but missing repro remains non-fileable."
                if not report.has_repro
                else "Internal note already includes repro/proof indicators.",
                blocking=False,
            )
        )
    return checks


def _apply_profile_blocking(checks: list[dict[str, str]], profile: str) -> list[dict[str, str]]:
    if profile != "internal-note":
        return checks
    relaxed = []
    for check in checks:
        item = dict(check)
        if item["id"] in {"repro", "attacker_path"} and item["status"] == "fail":
            item["status"] = "warn"
            item["blocking"] = "false"
            item["detail"] += (
                " Internal-note profile records this as triage debt instead of a filing blocker."
            )
        relaxed.append(item)
    return relaxed


def _has_duplicate_review_evidence(text: str) -> bool:
    return bool(
        re.search(
            r"(?i)\b(duplicate|prior art|github search|issue search|pr search|advisory|ghsa|cve search|not a duplicate|non-duplicate)\b",
            text,
        )
    )


def _repo_grounding_check(
    missing_files: list[str],
    missing_repo_refs: list[str],
    evidence_locations: list[dict[str, str]],
) -> dict[str, str]:
    grounding_kinds = {"file", "symbol", "endpoint"} | set(DANGEROUS_TERMS)
    grounding_locations = [item for item in evidence_locations if item["kind"] in grounding_kinds]
    grounded_categories = set()
    for item in grounding_locations:
        if item["kind"] in DANGEROUS_TERMS:
            grounded_categories.add("capability")
        else:
            grounded_categories.add(item["kind"])
    status = "fail" if missing_files else "warn" if missing_repo_refs else "pass"
    if missing_files or missing_repo_refs:
        detail = _join_check_detail(missing_files + missing_repo_refs)
    elif grounding_locations:
        detail = (
            f"Repo grounding is line-backed for {len(grounded_categories)}/{len(grounded_categories)} "
            "referenced files/symbols/endpoints/capabilities."
        )
    else:
        status = "warn"
        detail = "No line-backed repo references were extracted from the report."
    evidence = ", ".join(f"{item['file']}:{item['line']}" for item in grounding_locations[:8])
    return _check(
        "repo_grounding", "repo_grounding", status, detail, blocking=True, evidence=evidence
    )


def _attacker_path_check(
    report: ParsedReport, dangerous_hits: dict[str, list[str]]
) -> dict[str, str]:
    has_attacker_input = bool(report.attacker_mentions) and _has_attacker_controlled_input(
        report.text
    )
    has_entrypoint = report.has_attack_surface or any(
        endpoint.split(maxsplit=1)[0] in {"GET", "POST", "PUT", "PATCH", "DELETE"}
        for endpoint in report.endpoints
        if " " in endpoint
    )
    has_sink = bool(dangerous_hits) or any(
        term in report.text.lower() for term in RCE_TERMS + FILE_TERMS + SSRF_TERMS
    )
    has_source_to_sink = report.has_root_cause and report.has_exploit_chain
    missing_parts = []
    if not has_attacker_input:
        missing_parts.append("attacker input")
    if not has_entrypoint:
        missing_parts.append("entrypoint")
    if not has_sink:
        missing_parts.append("dangerous sink")
    if not has_source_to_sink:
        missing_parts.append("source-to-sink")
    if not missing_parts:
        return _check(
            "attacker_path",
            "attacker_path",
            "pass",
            "Report connects attacker input, entrypoint, sink, and source-to-sink explanation.",
            blocking=True,
        )
    return _check(
        "attacker_path",
        "attacker_path",
        "fail",
        "Missing attacker-path evidence: " + ", ".join(missing_parts) + ".",
        blocking=True,
    )


def _owasp_rationalization_check(
    report: ParsedReport,
    dangerous_hits: dict[str, list[str]],
    rules: list[tuple[str, tuple[str, ...]]],
    check_id: str,
    category: str,
) -> dict[str, str]:
    """Map report wording to OWASP categories without claiming a formal classification.

    This is intentionally deterministic and evidence-light: it gives reviewers a
    starting rationale for the closest OWASP Top 10 bucket while keeping the row
    non-blocking because final taxonomy choice is a human disclosure decision.
    """
    lower = report.text.lower()
    capability_terms = " ".join(term.lower() for terms in dangerous_hits.values() for term in terms)
    haystack = f"{lower} {capability_terms} {' '.join(report.impact_terms).lower()}"
    matches: list[str] = []
    for label, keywords in rules:
        matched_terms = [term for term in keywords if term in haystack]
        if matched_terms:
            matches.append(f"{label} ({', '.join(matched_terms[:3])})")
    matches = _dedupe(matches)[:4]
    if matches:
        detail = _owasp_detail_prefix(check_id) + ": " + "; ".join(matches) + "."
        return _check(check_id, category, "pass", detail, blocking=False)
    framework = "OWASP LLM Top 10" if check_id == "owasp_llm_top_10" else "OWASP Top 10"
    return _check(
        check_id,
        category,
        "warn",
        f"No strong {framework} mapping found; add taxonomy rationale or explain why none applies.",
        blocking=False,
    )


def _owasp_detail_prefix(check_id: str) -> str:
    if check_id == "owasp_llm_top_10":
        return "OWASP Top 10 for LLM Applications candidates"
    return "OWASP Top 10 candidates"


def _has_attacker_controlled_input(text: str) -> bool:
    return bool(
        re.search(
            r"(?i)\b(attacker[- ]controlled|user[- ]controlled|controls?|input|parameter|param|payload|prompt|url|request|body|header|file|workspace content)\b",
            text,
        )
    )


def _check(
    id: str,
    category: str,
    status: str,
    detail: str,
    *,
    blocking: bool = False,
    evidence: str = "",
) -> dict[str, str]:
    return {
        "id": id,
        "name": id,
        "category": category,
        "status": status,
        "blocking": "true" if blocking else "false",
        "detail": detail,
        "evidence": evidence,
    }


def _boolean_check(
    name: str, category: str, ok: bool, pass_detail: str, fail_detail: str
) -> dict[str, str]:
    return _check(
        name,
        category,
        "pass" if ok else "fail",
        pass_detail if ok else fail_detail,
        blocking=not ok,
    )


def _join_check_detail(items: list[str]) -> str:
    return "; ".join(items[:3]) + ("; ..." if len(items) > 3 else "")


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
                [
                    "gh",
                    "search",
                    "issues",
                    term,
                    "--repo",
                    owner_repo,
                    "--include-prs",
                    "--limit",
                    "5",
                    "--json",
                    "number,title,state,url",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=20,
            )
        except Exception as exc:  # pragma: no cover
            matches.append(f"GitHub duplicate search failed for `{term}`: {exc}")
            continue
        if proc.returncode != 0:
            matches.append(
                f"GitHub duplicate search failed for `{term}`: {proc.stderr.strip()[:160]}"
            )
            continue
        try:
            rows = json.loads(proc.stdout or "[]")
        except json.JSONDecodeError:
            rows = []
        for row in rows[:3]:
            matches.append(
                f"Possible related item for `{term}`: #{row['number']} {row['title']} ({row['state']}) {row['url']}"
            )
    return _dedupe(matches) or [
        "No obvious GitHub issue/PR duplicates found from simple search terms."
    ]


def vet(
    repo: Path, report_path: Path, owner_repo: str | None = None, profile: str = "preflight"
) -> VetResult:
    report = parse_report(report_path)
    confirmed, missing, evidence_locations, agent_context, dangerous_hits = collect_repo_evidence(
        repo, report
    )
    questions = generate_questions(report, agent_context, dangerous_hits)
    duplicates = duplicate_search(owner_repo, report)
    verdict, reason, rewrite = decide_verdict(report, missing, agent_context, profile)
    checks = build_evidence_checklist(
        report,
        missing,
        agent_context,
        evidence_locations,
        dangerous_hits,
        profile,
        duplicate_search_requested=bool(owner_repo),
    )
    blocking_failures = [
        check
        for check in checks
        if check.get("blocking") == "true" and check.get("status") == "fail"
    ]
    internal_triage_debt = any(
        check["id"] in {"repro", "attacker_path"}
        and check.get("status") == "warn"
        and "Internal-note profile records this as triage debt" in check.get("detail", "")
        for check in checks
    )
    if profile == "internal-note" and internal_triage_debt and verdict == "PASS":
        verdict = "NEEDS_WORK"
        reason = "Internal-note profile can track triage debt, but missing repro or source-to-sink evidence is not fileable yet."
        rewrite = "Keep as an internal note until a safe repro or code-path proof ties attacker input to impact."
    elif blocking_failures and verdict == "PASS":
        verdict = "NEEDS_WORK"
        failed_ids = ", ".join(check["id"] for check in blocking_failures[:6])
        reason = f"The report is grounded, but the `{profile}` profile still has blocking evidence gaps: {failed_ids}."
        rewrite = "Address the blocking checklist rows before filing under this profile."
    if (
        duplicates
        and not duplicates[0].startswith("No obvious")
        and not duplicates[0].startswith("GitHub duplicate check skipped")
        and verdict == "PASS"
    ):
        verdict = "DUPLICATE_RISK"
        reason = "The finding looks grounded, but similar public GitHub items may already exist."
    return VetResult(
        verdict=verdict,
        reason=reason,
        checks=checks,
        confirmed=_dedupe(confirmed),
        missing=_dedupe(missing),
        evidence_locations=evidence_locations,
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
            "has_affected_or_tested_version": report.has_affected_or_tested_version,
            "has_attack_surface": report.has_attack_surface,
            "has_root_cause": report.has_root_cause,
            "has_exploit_chain": report.has_exploit_chain,
            "has_safe_side_effect": report.has_safe_side_effect,
            "has_fix_guidance": report.has_fix_guidance,
            "profile": profile,
        },
    )


def render_markdown(result: VetResult) -> str:
    profile = result.parsed.get("profile", "preflight")
    lines = [
        "# Verifymate Result",
        "",
        f"Verdict: **{result.verdict}**",
        f"Profile: `{profile}`",
        "",
        "## One-line reason",
        "",
        result.reason,
        "",
        "## Checker result",
        "",
    ]
    blocking_failures = [
        item
        for item in result.checks
        if item.get("blocking") == "true" and item["status"] == "fail"
    ]
    warnings = [item for item in result.checks if item["status"] == "warn"]
    lines += [
        f"- Blocking failures: {len(blocking_failures)}",
        f"- Warnings: {len(warnings)}",
        "",
        "### Repo grounding",
    ]
    lines += [
        f"- **{item['status'].upper()}** `{item['id']}` — {item['detail']}"
        for item in result.checks
        if item.get("category") == "repo_grounding"
    ] or ["- No repo-grounding checks generated."]
    lines += ["", "### Attacker path"]
    lines += [
        f"- **{item['status'].upper()}** `{item['id']}` — {item['detail']}"
        for item in result.checks
        if item.get("category") == "attacker_path"
    ] or ["- No attacker-path checks generated."]
    lines += ["", "### OWASP rationalization"]
    lines += [
        f"- **{item['status'].upper()}** `{item['id']}` — {item['detail']}"
        for item in result.checks
        if item.get("category") in {"owasp", "owasp_llm"}
    ] or ["- No OWASP rationalization checks generated."]
    lines += ["", "## Evidence checklist", ""]
    lines += [
        f"- **{item['status'].upper()}** `{item['name']}` ({item.get('category', 'general')}) — {item['detail']}"
        for item in result.checks
    ] or ["- No checklist entries generated."]
    lines += [
        "",
        "## Confirmed from repo/report",
        "",
    ]
    lines += _bullet_list(result.confirmed, empty="No strong confirming evidence found.")
    if result.evidence_locations:
        lines += ["", "## Evidence locations", ""]
        lines += [
            f"- `{item['file']}:{item['line']}` — **{item['kind']}** `{item['term']}`: {item['snippet']}"
            for item in result.evidence_locations
        ]
    lines += ["", "## Missing or weak evidence", ""]
    lines += _bullet_list(
        result.missing, empty="No obvious blockers found by the lightweight checks."
    )
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


def _find_literal_location(
    files: Iterable[Path], needle: str, repo: Path, *, case_sensitive: bool = True
) -> tuple[str, int, str] | None:
    if not needle:
        return None
    needle_cmp = needle if case_sensitive else needle.lower()
    for path in files:
        try:
            rel = path.relative_to(repo).as_posix()
        except ValueError:
            rel = path.as_posix()
        for line_no, line in enumerate(_safe_read(path).splitlines(), 1):
            haystack = line if case_sensitive else line.lower()
            if needle_cmp in haystack:
                return rel, line_no, line.strip()[:200]
    return None


def _evidence_location(kind: str, term: str, file: str, line: int, snippet: str) -> dict[str, str]:
    return {
        "kind": kind,
        "term": term,
        "file": file,
        "line": str(line),
        "snippet": snippet,
    }


def _dedupe_locations(items: Iterable[dict[str, str]]) -> list[dict[str, str]]:
    seen: set[tuple[str, str, str, str]] = set()
    out: list[dict[str, str]] = []
    for item in items:
        key = (item["kind"], item["term"], item["file"], item["line"])
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out[:40]


def _dedupe(items: Iterable[str]) -> list[str]:
    seen = set()
    out = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _has_command(cmd: str) -> bool:
    return (
        subprocess.run(
            ["/usr/bin/env", "sh", "-c", f"command -v {cmd} >/dev/null 2>&1"], timeout=5
        ).returncode
        == 0
    )


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False
