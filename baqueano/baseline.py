"""Approved baseline and reconciliation.

`pin` records a fingerprint of every approved server configuration and tool
definition. `reconcile` compares the current inventory against it line by line
and classifies each difference as added, removed or modified - the same logic as
a financial reconciliation, applied to what an AI agent is allowed to call.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .checks import make_finding
from .models import Finding, Server, Tool

BASELINE_FORMAT = 1


def _hash(obj: object) -> str:
    canonical = json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def server_fingerprint(server: Server) -> dict:
    # Env and header *names* are pinned, values are not: rotating a secret is not drift.
    return {
        "transport": server.transport,
        "command": server.command,
        "args": server.args,
        "url": server.url,
        "env_keys": sorted(server.env),
        "header_keys": sorted(server.headers),
    }


def tool_fingerprint(tool: Tool) -> dict:
    return {"name": tool.name, "description": tool.description, "inputSchema": tool.input_schema}


def build_baseline(servers: list[Server]) -> dict:
    data: dict = {
        "format": BASELINE_FORMAT,
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "generator": f"baqueano {__version__}",
        "servers": {},
    }
    for server in servers:
        cfg = server_fingerprint(server)
        entry: dict = {"config": cfg, "config_hash": _hash(cfg)}
        if server.tools_known:
            entry["tools"] = {
                t.name: {"hash": _hash(tool_fingerprint(t)), "definition": tool_fingerprint(t)}
                for t in server.tools
            }
        data["servers"][server.name] = entry
    return data


def save_baseline(servers: list[Server], path: str | Path) -> dict:
    data = build_baseline(servers)
    Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return data


def load_baseline(path: str | Path) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("format") != BASELINE_FORMAT or "servers" not in data:
        raise ValueError(f"{path} is not a baqueano baseline (format {BASELINE_FORMAT})")
    return data


@dataclass
class Reconciliation:
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    modified: list[str] = field(default_factory=list)
    unchanged: int = 0
    findings: list[Finding] = field(default_factory=list)

    @property
    def total_compared(self) -> int:
        return len(self.added) + len(self.removed) + len(self.modified) + self.unchanged


def _changed_fields(old: dict, new: dict) -> list[str]:
    return sorted(k for k in set(old) | set(new) if old.get(k) != new.get(k))


def _short(text: str, n: int = 90) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= n else text[: n - 1] + "…"


def reconcile(servers: list[Server], baseline: dict) -> Reconciliation:
    rec = Reconciliation()
    approved: dict = baseline["servers"]
    current = {s.name: s for s in servers}

    for name in sorted(set(approved) - set(current)):
        rec.removed.append(f"server:{name}")
        rec.findings.append(make_finding(
            "BQ-015", name, f"server:{name}", "Server present in baseline, absent now"))

    for name, server in current.items():
        if name not in approved:
            rec.added.append(f"server:{name}")
            rec.findings.append(make_finding(
                "BQ-014", name, f"server:{name}", "Server not present in approved baseline"))
            continue

        entry = approved[name]
        cfg = server_fingerprint(server)
        if entry["config_hash"] == _hash(cfg):
            rec.unchanged += 1
        else:
            changed = _changed_fields(entry["config"], cfg)
            rec.modified.append(f"server:{name}")
            detail = "; ".join(
                f"{k}: {_short(entry['config'].get(k))} -> {_short(cfg.get(k))}" for k in changed)
            rec.findings.append(make_finding(
                "BQ-016", name, f"config:{name}", f"Changed {', '.join(changed)} ({detail})"))

        if "tools" not in entry or not server.tools_known:
            continue
        old_tools: dict = entry["tools"]
        new_tools = {t.name: t for t in server.tools}

        for tname in sorted(set(old_tools) - set(new_tools)):
            rec.removed.append(f"tool:{name}/{tname}")
            rec.findings.append(make_finding(
                "BQ-015", name, f"tool:{tname}", "Tool present in baseline, absent now", tool=tname))
        for tname, tool in new_tools.items():
            if tname not in old_tools:
                rec.added.append(f"tool:{name}/{tname}")
                rec.findings.append(make_finding(
                    "BQ-014", name, f"tool:{tname}", "Tool not present in approved baseline",
                    tool=tname))
                continue
            fp = tool_fingerprint(tool)
            if old_tools[tname]["hash"] == _hash(fp):
                rec.unchanged += 1
                continue
            old_def = old_tools[tname]["definition"]
            changed = _changed_fields(old_def, fp)
            rec.modified.append(f"tool:{name}/{tname}")
            evidence = f"Changed {', '.join(changed)}"
            if "description" in changed:
                evidence += (f". Before: \"{_short(old_def['description'])}\" "
                             f"After: \"{_short(fp['description'])}\"")
            rec.findings.append(make_finding(
                "BQ-013", name, f"tool:{tname}", evidence, tool=tname))
    return rec
