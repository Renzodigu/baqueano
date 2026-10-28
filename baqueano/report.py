"""Render audit results as Markdown report, JSON, and a CSV risk register."""
from __future__ import annotations

import csv
import io
import json
import re
from collections import Counter

from . import __version__
from .audit import AuditResult
from .models import Severity
from .rules import ISO27001_A, OWASP_MCP_TOP10, OWASP_NOT_STATIC, RULES

POSTURE = {
    Severity.CRITICAL: "Critical - stop using the affected servers until remediated",
    Severity.HIGH: "High - remediate before production use",
    Severity.MEDIUM: "Moderate - plan remediation in the next change window",
    Severity.LOW: "Low - hardening opportunities only",
    Severity.INFO: "Informational - no security issues detected",
}

# Default remediation window per severity, for the risk register.
TARGET_DAYS = {Severity.CRITICAL: 1, Severity.HIGH: 7, Severity.MEDIUM: 30,
               Severity.LOW: 90, Severity.INFO: None}


_HIDDEN = re.compile(r"[\x00-\x08\x0b-\x1f\x7f\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff"
                     r"\U000e0000-\U000e007f]")


def _visible(text: str) -> str:
    """Show hidden characters as escapes: the reviewer must see what the model would read."""
    return _HIDDEN.sub(lambda m: f"\\u{ord(m.group()):04x}" if ord(m.group()) < 0x10000
                       else f"\\U{ord(m.group()):08x}", str(text))


def _md(text: str) -> str:
    return _visible(text).replace("|", "\\|").replace("\n", " ")


def _code(text: str, in_table: bool = False) -> str:
    """Untrusted text (tool names, descriptions) as an inline code span, so it cannot inject Markdown or HTML."""
    text = _visible(text).replace("\n", " ").replace("\r", " ")
    fence = "`" * (max((len(r) for r in re.findall(r"`+", text)), default=0) + 1)
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    span = f"{fence}{pad}{text}{pad}{fence}"
    return span.replace("|", "\\|") if in_table else span


def _iso(codes: list[str]) -> str:
    return ", ".join(f"A.{c}" for c in codes)


def to_markdown(result: AuditResult) -> str:
    out: list[str] = []
    w = out.append
    counts = result.count_by_severity()
    highest = result.highest

    w("# MCP Security Audit Report\n")
    w(f"- **Generated:** {result.generated} by baqueano {__version__}")
    for k, v in result.inputs.items():
        w(f"- **{k.capitalize()}:** `{v}`")
    w(f"- **Scope:** {len(result.servers)} servers, {result.tool_count} tool definitions\n")

    w("## Executive summary\n")
    if highest is None:
        w("No findings. " + POSTURE[Severity.INFO] + ".\n")
    else:
        w(f"**Overall risk posture: {POSTURE[highest]}.**\n")
        w(f"The audit produced {len(result.findings)} findings. "
          "Severity distribution:\n")
        w("| Severity | Findings |")
        w("|---|---|")
        for sev, n in counts.items():
            w(f"| {sev.label} | {n} |")
        w("")
        per_server = Counter(f.server for f in result.findings if f.severity >= Severity.HIGH)
        if per_server:
            top = ", ".join(f"`{s}` ({n})" for s, n in per_server.most_common(3))
            w(f"Servers with the most high or critical findings: {top}.\n")

    w("## Coverage by OWASP MCP Top 10\n")
    w("| ID | Risk | Findings | Note |")
    w("|---|---|---|---|")
    by_owasp = Counter(o for f in result.findings for o in f.owasp)
    for code, name in OWASP_MCP_TOP10.items():
        note = OWASP_NOT_STATIC.get(code, "")
        w(f"| {code} | {name} | {by_owasp.get(code, 0)} | {note} |")
    w("")

    if result.reconciliation:
        rec = result.reconciliation
        w("## Baseline reconciliation\n")
        w(f"{rec.total_compared} components compared against the approved baseline.\n")
        w("| Result | Count | Items |")
        w("|---|---|---|")
        w(f"| Unchanged | {rec.unchanged} | |")
        for label, items in (("Added", rec.added), ("Modified", rec.modified), ("Removed", rec.removed)):
            w(f"| {label} | {len(items)} | {_md(', '.join(items))} |")
        w("")

    if result.findings:
        w("## Findings register\n")
        w("| ID | Severity | Server | Tool | Finding | OWASP | ISO 27001 |")
        w("|---|---|---|---|---|---|---|")
        for f in result.findings:
            tool = _code(f.tool, in_table=True) if f.tool else "-"
            w(f"| {f.finding_id} | {f.severity.label} | {_code(f.server, in_table=True)} | {tool} | "
              f"{_md(f.title)} | {', '.join(f.owasp)} | {_iso(f.iso27001)} |")
        w("")

        w("## Finding details\n")
        for f in result.findings:
            w(f"### {f.finding_id} - {f.title}\n")
            w(f"- **Severity:** {f.severity.label}  ")
            w(f"- **Rule:** {f.rule_id}  ")
            w(f"- **Server / tool:** {_code(f.server)}" + (f" / {_code(f.tool)}" if f.tool else "") + "  ")
            w(f"- **Location:** {_code(f.location)}  ")
            w(f"- **Evidence:** {_code(f.evidence)}  ")
            w("- **OWASP MCP:** " + ", ".join(f"{o} {OWASP_MCP_TOP10[o]}" for o in f.owasp) + "  ")
            w("- **ISO 27001:2022:** " + "; ".join(
                f"A.{c} {ISO27001_A.get(c, '')}" for c in f.iso27001) + "  ")
            w(f"- **Recommendation:** {f.recommendation}\n")

    w("## Methodology and limitations\n")
    w("Static review of the MCP client configuration and of the tool definitions the "
      "servers expose (`tools/list`). Rules are pattern-based and can produce false "
      "positives or miss obfuscated payloads; every finding should be confirmed by a "
      "reviewer before it is closed or accepted. The audit does not execute tools, inspect "
      "server source code, or observe runtime behaviour, so logging (MCP08) and context "
      "isolation between sessions (MCP10) need a separate review.\n")
    w("Rule catalogue: " + ", ".join(f"{r.id}" for r in RULES.values()) + ".")
    return "\n".join(out) + "\n"


def to_json(result: AuditResult) -> str:
    rec = result.reconciliation
    data = {
        "generator": f"baqueano {__version__}",
        "generated": result.generated,
        "inputs": result.inputs,
        "scope": {"servers": [s.name for s in result.servers], "tool_count": result.tool_count},
        "summary": {s.label: n for s, n in result.count_by_severity().items()},
        "highest_severity": result.highest.label if result.highest is not None else None,
        "reconciliation": None if rec is None else {
            "unchanged": rec.unchanged, "added": rec.added,
            "modified": rec.modified, "removed": rec.removed,
        },
        "findings": [f.to_dict() for f in result.findings],
    }
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


REGISTER_COLUMNS = [
    "Finding ID", "Rule", "Severity", "Server", "Tool", "Finding", "Evidence", "Location",
    "OWASP MCP", "ISO 27001 controls", "Corrective action", "Target (days)",
    "Owner", "Status", "Treatment",
]


def csv_safe(value):
    """Tool names and descriptions come from the server: =HYPERLINK(...) must not become a live formula."""
    if isinstance(value, str) and value.startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + value
    return value


def to_risk_register(result: AuditResult) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(REGISTER_COLUMNS)
    for f in result.findings:
        days = TARGET_DAYS[f.severity]
        writer.writerow(csv_safe(v) for v in [
            f.finding_id, f.rule_id, f.severity.label, f.server, f.tool or "", f.title,
            f.evidence, f.location, "; ".join(f.owasp), "; ".join(_iso(f.iso27001).split(", ")),
            f.recommendation, "" if days is None else days, "", "Open", "",
        ])
    return buf.getvalue()
