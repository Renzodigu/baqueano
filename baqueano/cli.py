"""Command-line interface.

    baqueano scan --config mcp.json [--tools tools.json] [--baseline baseline.json]
                  [--out-dir reports/] [--format md,html,json,csv] [--fail-on high]
    baqueano pin  --config mcp.json [--tools tools.json] --output baseline.json
    baqueano rules
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .audit import run_audit
from .baseline import save_baseline
from .html_report import to_html
from .loader import ConfigError, load
from .models import Severity
from .report import to_json, to_markdown, to_risk_register
from .rules import RULES

FORMATS = {
    "md": ("audit-report.md", to_markdown),
    "html": ("audit-report.html", to_html),
    "json": ("audit-report.json", to_json),
    "csv": ("risk-register.csv", to_risk_register),
}


def _scan(args: argparse.Namespace) -> int:
    result = run_audit(args.config, args.tools, args.baseline)
    formats = [f.strip() for f in args.format.split(",") if f.strip()]
    unknown = set(formats) - set(FORMATS)
    if unknown:
        raise ValueError(f"Unknown format(s): {', '.join(sorted(unknown))}")

    if args.out_dir:
        out = Path(args.out_dir)
        out.mkdir(parents=True, exist_ok=True)
        for fmt in formats:
            filename, render = FORMATS[fmt]
            # newline="": the csv module already ends rows with \r\n; on Windows text mode would make it \r\r\n
            (out / filename).write_text(render(result), encoding="utf-8", newline="" if fmt == "csv" else None)
    else:
        for fmt in formats:
            sys.stdout.write(FORMATS[fmt][1](result))

    counts = result.count_by_severity()
    summary = ", ".join(f"{n} {s.label.lower()}" for s, n in counts.items() if n)
    print(f"[baqueano] {len(result.servers)} servers, {result.tool_count} tools, "
          f"{len(result.findings)} findings" + (f" ({summary})" if summary else ""),
          file=sys.stderr)
    if args.out_dir:
        print(f"[baqueano] reports written to {args.out_dir}", file=sys.stderr)

    if args.fail_on:
        threshold = Severity.parse(args.fail_on)
        if any(f.severity >= threshold for f in result.findings):
            return 1
    return 0


def _pin(args: argparse.Namespace) -> int:
    servers = load(args.config, args.tools)
    data = save_baseline(servers, args.output)
    tools = sum(len(e.get("tools", {})) for e in data["servers"].values())
    print(f"[baqueano] baseline pinned: {len(data['servers'])} servers, {tools} tools "
          f"-> {args.output}", file=sys.stderr)
    return 0


def _rules(_: argparse.Namespace) -> int:
    for r in RULES.values():
        print(f"{r.id}  {r.severity.label:<8}  {','.join(r.owasp):<11}  {r.title}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="baqueano",
        description="GRC-oriented security auditor for MCP servers and AI agent tooling.")
    p.add_argument("--version", action="version", version=f"baqueano {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="audit an MCP configuration and its tools")
    scan.add_argument("--config", "-c", required=True, help="MCP client config (mcpServers/servers)")
    scan.add_argument("--tools", "-t", help="tool manifest (tools/list output per server)")
    scan.add_argument("--baseline", "-b", help="approved baseline to reconcile against")
    scan.add_argument("--out-dir", "-o", help="write reports to this directory instead of stdout")
    scan.add_argument("--format", "-f", default="md", help="comma-separated: md,html,json,csv (default md)")
    scan.add_argument("--fail-on", help="exit 1 if any finding is at or above this severity (CI)")
    scan.set_defaults(func=_scan)

    pin = sub.add_parser("pin", help="record the current, reviewed state as the approved baseline")
    pin.add_argument("--config", "-c", required=True)
    pin.add_argument("--tools", "-t")
    pin.add_argument("--output", "-o", required=True)
    pin.set_defaults(func=_pin)

    rules = sub.add_parser("rules", help="list the rule catalogue")
    rules.set_defaults(func=_rules)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (ConfigError, ValueError) as exc:
        print(f"[baqueano] error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
