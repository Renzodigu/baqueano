"""Rule catalogue with framework mappings.

Every rule maps to the OWASP MCP Top 10 (2025 beta) and to ISO/IEC 27001:2022
Annex A controls, so each finding can go straight into a risk register.
"""
from __future__ import annotations

from dataclasses import dataclass

from .models import Severity

OWASP_MCP_TOP10 = {
    "MCP01": "Token Mismanagement & Secret Exposure",
    "MCP02": "Privilege Escalation via Scope Creep",
    "MCP03": "Tool Poisoning",
    "MCP04": "Software Supply Chain Attacks & Dependency Tampering",
    "MCP05": "Command Injection & Execution",
    "MCP06": "Prompt Injection via Contextual Payloads",
    "MCP07": "Insufficient Authentication & Authorization",
    "MCP08": "Lack of Audit and Telemetry",
    "MCP09": "Shadow MCP Servers",
    "MCP10": "Context Injection & Over-Sharing",
}

# Categories a static config/manifest audit cannot assess on its own.
OWASP_NOT_STATIC = {
    "MCP08": "Requires reviewing server and client logging at runtime.",
    "MCP10": "Partially covered (sensitive references in tool metadata); "
    "context sharing between sessions needs runtime review.",
}

ISO27001_A = {
    "5.9": "Inventory of information and other associated assets",
    "5.15": "Access control",
    "5.17": "Authentication information",
    "5.21": "Managing information security in the ICT supply chain",
    "8.2": "Privileged access rights",
    "8.3": "Information access restriction",
    "8.5": "Secure authentication",
    "8.7": "Protection against malware",
    "8.12": "Data leakage prevention",
    "8.19": "Installation of software on operational systems",
    "8.20": "Networks security",
    "8.24": "Use of cryptography",
    "8.28": "Secure coding",
    "8.32": "Change management",
}


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    owasp: tuple[str, ...]
    iso27001: tuple[str, ...]
    recommendation: str


RULES: dict[str, Rule] = {
    r.id: r
    for r in [
        Rule(
            "BQ-001",
            "Hard-coded secret in server configuration",
            Severity.HIGH,
            ("MCP01",),
            ("5.17", "8.12"),
            "Remove the literal secret, rotate it, and inject it at runtime from a "
            "secrets manager or an environment variable reference (e.g. ${TOKEN}).",
        ),
        Rule(
            "BQ-002",
            "Unpinned server package or image",
            Severity.MEDIUM,
            ("MCP04",),
            ("5.21", "8.19"),
            "Pin the exact version (or image digest) that was reviewed, and update it "
            "only through change management after a new review.",
        ),
        Rule(
            "BQ-003",
            "Remote server reached over unencrypted HTTP",
            Severity.HIGH,
            ("MCP07",),
            ("8.20", "8.24"),
            "Use HTTPS (TLS 1.2+) for every non-local MCP endpoint.",
        ),
        Rule(
            "BQ-004",
            "Remote server with no client-side authentication configured",
            Severity.LOW,
            ("MCP07",),
            ("8.5", "5.15"),
            "Confirm the server enforces OAuth 2.1 as defined in the MCP authorization "
            "spec, or configure a credential; reject anonymous access to remote servers.",
        ),
        Rule(
            "BQ-005",
            "Over-broad filesystem scope",
            Severity.HIGH,
            ("MCP02",),
            ("8.2", "8.3"),
            "Restrict the server to the specific project directories it needs "
            "(least privilege); never expose the filesystem root or a home directory.",
        ),
        Rule(
            "BQ-006",
            "Tool grants arbitrary command execution",
            Severity.HIGH,
            ("MCP05", "MCP02"),
            ("8.2", "8.28"),
            "Replace generic execution with narrow, purpose-built tools; if unavoidable, "
            "run it sandboxed, with an allowlist of commands and human approval per call.",
        ),
        Rule(
            "BQ-007",
            "Instruction-like text in tool metadata (tool poisoning)",
            Severity.HIGH,
            ("MCP03", "MCP06"),
            ("5.21", "8.7"),
            "Treat the server as untrusted: disable it, report it to the vendor, and only "
            "re-enable a reviewed version whose metadata is purely descriptive.",
        ),
        Rule(
            "BQ-008",
            "Hidden or invisible content in tool metadata",
            Severity.HIGH,
            ("MCP03",),
            ("5.21", "8.7"),
            "Reject metadata with invisible Unicode, HTML comments or padding; what the "
            "model reads must be exactly what a human reviewer sees.",
        ),
        Rule(
            "BQ-009",
            "Tool metadata references sensitive files or credentials",
            Severity.CRITICAL,
            ("MCP03", "MCP10"),
            ("8.12", "5.17"),
            "Disable the server immediately and check whether those files were read; "
            "rotate any credential that may have been exposed.",
        ),
        Rule(
            "BQ-010",
            "Cross-server tool shadowing",
            Severity.HIGH,
            ("MCP06", "MCP03"),
            ("5.15", "5.21"),
            "A tool must never describe how other servers' tools should behave. Remove "
            "the server or isolate it in a separate client profile.",
        ),
        Rule(
            "BQ-011",
            "Tool name collision across servers",
            Severity.MEDIUM,
            ("MCP06",),
            ("5.15",),
            "Rename or disable one of the tools so the agent cannot be steered to the "
            "wrong implementation.",
        ),
        Rule(
            "BQ-012",
            "Unconstrained high-risk input parameter",
            Severity.MEDIUM,
            ("MCP05",),
            ("8.28",),
            "Constrain the parameter (enum, pattern, maxLength, allowed roots) and "
            "validate it server-side; never pass it unsanitised to a shell, SQL engine "
            "or HTTP client.",
        ),
        Rule(
            "BQ-013",
            "Tool definition changed since approved baseline (possible rug pull)",
            Severity.HIGH,
            ("MCP04", "MCP03"),
            ("8.32", "5.21"),
            "Block the changed definition until it is reviewed; approve it by "
            "re-pinning the baseline only after review.",
        ),
        Rule(
            "BQ-014",
            "Server or tool not in approved baseline",
            Severity.MEDIUM,
            ("MCP09",),
            ("5.9", "8.32"),
            "Review and approve the new component, then add it to the baseline; "
            "otherwise remove it.",
        ),
        Rule(
            "BQ-015",
            "Approved server or tool missing from current inventory",
            Severity.INFO,
            ("MCP09",),
            ("5.9",),
            "Confirm the removal was intended and update the baseline and asset inventory.",
        ),
        Rule(
            "BQ-016",
            "Server configuration changed since approved baseline",
            Severity.HIGH,
            ("MCP04",),
            ("8.32",),
            "Review the new command, arguments or endpoint and re-pin the baseline only "
            "after approval.",
        ),
    ]
}
