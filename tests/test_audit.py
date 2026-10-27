import csv
import io
import json
from pathlib import Path

import pytest

from baqueano.audit import run_audit
from baqueano.baseline import load_baseline, reconcile, save_baseline
from baqueano.cli import main
from baqueano.loader import ConfigError, load, parse_config
from baqueano.report import REGISTER_COLUMNS, to_json, to_markdown, to_risk_register

DEMO = Path(__file__).resolve().parent.parent / "examples" / "yerba-labs"


def test_parse_vscode_and_remote_shapes():
    servers = parse_config({"servers": {
        "a": {"command": "npx", "args": ["x@1.0.0"]},
        "b": {"type": "sse", "url": "https://x.example/sse"},
    }})
    assert [(s.name, s.transport) for s in servers] == [("a", "stdio"), ("b", "sse")]


def test_invalid_config_raises():
    with pytest.raises(ConfigError):
        parse_config({"nothing": {}})


def test_demo_audit_end_to_end():
    result = run_audit(DEMO / "mcp.json", DEMO / "tools.json", DEMO / "baseline.json")
    found = {f.rule_id for f in result.findings}
    # Every scenario planted in the demo must be detected.
    for rule in ["BQ-001", "BQ-002", "BQ-003", "BQ-004", "BQ-005", "BQ-006", "BQ-007",
                 "BQ-008", "BQ-009", "BQ-010", "BQ-011", "BQ-012", "BQ-013", "BQ-014", "BQ-016"]:
        assert rule in found, rule
    # Clean, well-configured servers stay clean apart from low-risk parameter notes.
    assert not [f for f in result.findings if f.server == "mail"]
    ids = [f.finding_id for f in result.findings]
    assert ids == [f"F-{i:03d}" for i in range(1, len(ids) + 1)]
    sev = [f.severity for f in result.findings]
    assert sev == sorted(sev, reverse=True)


def test_reconciliation_classifies_changes():
    rec = reconcile(load(DEMO / "mcp.json", DEMO / "tools.json"), load_baseline(DEMO / "baseline.json"))
    assert rec.added == ["tool:weather/get_alerts"]
    assert set(rec.modified) == {"tool:crm/add_note", "tool:weather/get_forecast", "server:devtools"}
    assert rec.removed == []


def test_rotating_a_secret_is_not_drift(tmp_path):
    servers = load(DEMO / "mcp.json", DEMO / "tools.json")
    save_baseline(servers, tmp_path / "b.json")
    servers[1].env["CRM_API_KEY"] = "rotated-value-123456"
    rec = reconcile(servers, load_baseline(tmp_path / "b.json"))
    assert rec.modified == [] and rec.added == [] and rec.removed == []


def test_removed_server_is_reported(tmp_path):
    servers = load(DEMO / "mcp.json")
    save_baseline(servers, tmp_path / "b.json")
    rec = reconcile(servers[1:], load_baseline(tmp_path / "b.json"))
    assert rec.removed == ["server:files"]


def test_reports_render():
    result = run_audit(DEMO / "mcp.json", DEMO / "tools.json", DEMO / "baseline.json")
    md = to_markdown(result)
    assert "Overall risk posture: Critical" in md and "Baseline reconciliation" in md
    data = json.loads(to_json(result))
    assert data["highest_severity"] == "Critical"
    assert len(data["findings"]) == len(result.findings)
    rows = list(csv.reader(io.StringIO(to_risk_register(result))))
    assert rows[0] == REGISTER_COLUMNS and len(rows) == len(result.findings) + 1
    # Secrets are masked in every output.
    for text in (md, to_json(result), to_risk_register(result)):
        assert "yl_live_9f2c7a41d0b84e6aa1c3" not in text


def test_cli_fail_on_and_outputs(tmp_path, capsys):
    code = main(["scan", "-c", str(DEMO / "mcp.json"), "-t", str(DEMO / "tools.json"),
                 "-o", str(tmp_path), "-f", "md,json,csv", "--fail-on", "critical"])
    assert code == 1
    assert {p.name for p in tmp_path.iterdir()} == {
        "audit-report.md", "audit-report.json", "risk-register.csv"}


def test_cli_clean_config_passes(tmp_path):
    cfg = tmp_path / "mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {"ok": {"command": "npx", "args": ["srv@1.2.3"]}}}))
    assert main(["scan", "-c", str(cfg), "--fail-on", "low", "-o", str(tmp_path / "r")]) == 0


def test_cli_bad_input_returns_2(tmp_path):
    assert main(["scan", "-c", str(tmp_path / "missing.json")]) == 2
