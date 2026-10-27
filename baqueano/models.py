"""Core data structures: servers, tools, findings and severities."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.capitalize()

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            valid = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"Unknown severity '{value}'. Use one of: {valid}") from exc


@dataclass
class Tool:
    name: str
    description: str = ""
    input_schema: dict = field(default_factory=dict)


@dataclass
class Server:
    name: str
    transport: str = "stdio"  # stdio | http | sse
    command: str | None = None
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    url: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    tools: list[Tool] = field(default_factory=list)
    tools_known: bool = False  # True when a tool manifest was provided for this server


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    server: str
    location: str
    evidence: str
    recommendation: str
    owasp: list[str]
    iso27001: list[str]
    tool: str | None = None
    finding_id: str = ""

    def to_dict(self) -> dict:
        data = asdict(self)
        data["severity"] = self.severity.label
        return data
