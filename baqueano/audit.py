"""Run a full audit: load inputs, run checks, reconcile against a baseline."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .baseline import Reconciliation, load_baseline, reconcile
from .checks import run_checks
from .loader import load
from .models import Finding, Server, Severity


@dataclass
class AuditResult:
    servers: list[Server]
    findings: list[Finding]
    inputs: dict[str, str]
    reconciliation: Reconciliation | None = None
    generated: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))

    @property
    def tool_count(self) -> int:
        return sum(len(s.tools) for s in self.servers)

    def count_by_severity(self) -> dict[Severity, int]:
        counts = {s: 0 for s in sorted(Severity, reverse=True)}
        for f in self.findings:
            counts[f.severity] += 1
        return counts

    @property
    def highest(self) -> Severity | None:
        return max((f.severity for f in self.findings), default=None)


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen, out = set(), []
    for f in findings:
        key = (f.rule_id, f.server, f.tool, f.location, f.evidence)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def run_audit(
    config: str | Path,
    tools: str | Path | None = None,
    baseline: str | Path | None = None,
) -> AuditResult:
    servers = load(config, tools)
    findings = run_checks(servers)
    rec = None
    if baseline:
        rec = reconcile(servers, load_baseline(baseline))
        findings.extend(rec.findings)

    findings = _dedupe(findings)
    findings.sort(key=lambda f: (-f.severity, f.server, f.rule_id, f.tool or "", f.location))
    for i, f in enumerate(findings, 1):
        f.finding_id = f"F-{i:03d}"

    inputs = {"config": str(config)}
    if tools:
        inputs["tools"] = str(tools)
    if baseline:
        inputs["baseline"] = str(baseline)
    return AuditResult(servers=servers, findings=findings, inputs=inputs, reconciliation=rec)
