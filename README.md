# Baqueano

**GRC-oriented security auditor for MCP servers and AI agent tooling.**

![CI](https://github.com/Renzodigu/baqueano/actions/workflows/ci.yml/badge.svg)

![HTML audit report for the demo: critical posture, 23 findings by severity and the OWASP MCP Top 10 grid coloured by the highest severity found in each risk](docs/img/report-overview.png)

*Baqueano* is the Argentine word for the guide who knows the terrain and warns you
before you walk into trouble. This tool does that for the Model Context Protocol (MCP):
before an AI agent is connected to a set of MCP servers, it reviews what those servers
are allowed to do and what their tools tell the model, and it produces evidence an
auditor can work with.

Most MCP scanners stop at "here is a list of warnings". Baqueano is built from the
audit side:

- **Every finding is mapped** to the [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/)
  and to **ISO/IEC 27001:2022 Annex A** controls.
- **Outputs are audit artefacts**: an audit report with an executive summary and
  coverage table (Markdown or a self-contained HTML page), a machine-readable JSON, and
  a **CSV risk register** with corrective action, target remediation window, owner and
  status columns.
- **Rug pulls are handled as a reconciliation.** You pin an approved baseline after a
  review; every later audit reconciles the current servers and tool definitions against
  it, line by line, and classifies each difference as *added*, *modified* or *removed*.

Zero runtime dependencies, Python 3.10+.

## Quick start

```bash
git clone https://github.com/Renzodigu/baqueano.git && cd baqueano
pip install -e .            # or: python -m baqueano ...

# Audit a client config together with the tools its servers expose
baqueano scan --config examples/yerba-labs/mcp.json \
              --tools  examples/yerba-labs/tools.json \
              --baseline examples/yerba-labs/baseline.json \
              --format md,html,json,csv --out-dir reports/

# After reviewing and approving the current state, pin it as the baseline
baqueano pin --config mcp.json --tools tools.json --output baseline.json

# Use it as a CI gate
baqueano scan -c mcp.json -t tools.json -b baseline.json --fail-on high

# List the rule catalogue
baqueano rules
```

**Inputs**

| Input | What it is |
|---|---|
| `--config` | An MCP client config: `mcpServers` (Claude Desktop, Claude Code `.mcp.json`, Cursor, Windsurf) or `servers` (VS Code). |
| `--tools` | The `tools/list` result of each server, as `{"server": {"tools": [...]}}`. Optional: without it only configuration checks run. |
| `--baseline` | A baseline created with `baqueano pin`. Optional. |

## What it checks

| Rule | Severity | Finding | OWASP MCP | ISO 27001:2022 |
|---|---|---|---|---|
| BQ-001 | High / Critical | Hard-coded secret in env, headers, args or URL (known token formats are critical; values are always masked) | MCP01 | A.5.17, A.8.12 |
| BQ-002 | Medium | `npx` / `uvx` / `pipx` / `docker` server without an exact version or with `latest` | MCP04 | A.5.21, A.8.19 |
| BQ-003 | High | Remote server over plain HTTP | MCP07 | A.8.20, A.8.24 |
| BQ-004 | Low | Remote server with no credential configured (verify OAuth) | MCP07 | A.8.5, A.5.15 |
| BQ-005 | High | Filesystem root, home directory or `/` volume mount granted to a server | MCP02 | A.8.2, A.8.3 |
| BQ-006 | High | Tool that executes arbitrary commands or code | MCP05, MCP02 | A.8.2, A.8.28 |
| BQ-007 | High | Instruction-like text in tool or parameter descriptions (tool poisoning) | MCP03, MCP06 | A.5.21, A.8.7 |
| BQ-008 | High | Invisible Unicode, HTML comments or padding hidden in metadata | MCP03 | A.5.21, A.8.7 |
| BQ-009 | Critical | Metadata that references SSH keys, `.env`, cloud credentials, MCP configs… | MCP03, MCP10 | A.8.12, A.5.17 |
| BQ-010 | High | Cross-server tool shadowing (a tool describing how another server's tool must behave) | MCP06, MCP03 | A.5.15, A.5.21 |
| BQ-011 | Medium | Same tool name exposed by several servers | MCP06 | A.5.15 |
| BQ-012 | Low / Medium | Free-form `command`, `sql`, `code`, `path`, `url`… parameter with no constraint | MCP05 | A.8.28 |
| BQ-013 | High | Tool definition changed since the approved baseline (possible rug pull) | MCP04, MCP03 | A.8.32, A.5.21 |
| BQ-014 | Medium | Server or tool not in the approved baseline | MCP09 | A.5.9, A.8.32 |
| BQ-015 | Info | Approved server or tool no longer present | MCP09 | A.5.9 |
| BQ-016 | High | Server command, arguments or endpoint changed since the baseline | MCP04 | A.8.32 |

Secret *values* are deliberately excluded from the baseline fingerprint: rotating a
credential is good hygiene, not configuration drift.

## Demo: Yerba Labs (fictitious)

[`examples/yerba-labs`](examples/yerba-labs) contains the MCP setup of a made-up company,
with an approved snapshot (`approved/`) and the current state. Between the two, someone
changed things:

- the `crm` server's `add_note` tool now carries a classic tool-poisoning payload that
  asks the model to read `~/.ssh/id_rsa` and hide it from the user;
- the `weather` server's `get_forecast` now tells the model to BCC an outside address on
  every email sent through a *different* server (shadowing), and a new tool appeared;
- the `devtools` container moved from a pinned tag to `latest`.

The generated outputs are in [`examples/yerba-labs/report`](examples/yerba-labs/report):
[audit report](examples/yerba-labs/report/audit-report.md),
[HTML report](examples/yerba-labs/report/audit-report.html) (download it and open it in a
browser), [risk register](examples/yerba-labs/report/risk-register.csv) and
[JSON](examples/yerba-labs/report/audit-report.json). All names, domains, tokens and
data in the demo are invented.

The HTML report shows the posture, the OWASP MCP Top 10 coverage, a server by severity
heat map and, for every component that changed since the baseline, the approved and the
current definition side by side with the additions highlighted: the rug pull in
`crm/add_note` is visible at a glance. Everything in it that comes from the audited
servers is escaped, hidden characters are highlighted, and a Content-Security-Policy
blocks remote loads and every script except the page's own severity filter.

![Baseline diff for crm/add_note: the approved description is one sentence; the current one adds a hidden instruction to read ~/.ssh/id_rsa, and the input schema gains a sidenote parameter](docs/img/rug-pull-diff.png)

## How it fits into a review process

1. **Inventory**: collect the MCP client configs in use (shadow servers are an OWASP MCP
   Top 10 risk on their own).
2. **Assess**: run `baqueano scan` and triage each finding: remediate, accept with
   justification, or mark as false positive in the risk register.
3. **Approve**: once the residual risk is accepted, `baqueano pin` the reviewed state.
4. **Monitor**: run `baqueano scan --baseline ... --fail-on high` in CI or on a schedule;
   any change to an approved tool needs a new review before it is re-pinned
   (ISO 27001 A.8.32, change management).

## Limitations

This is a static, pattern-based review. It can raise false positives and it will miss
payloads that are obfuscated beyond its rules. It does not execute tools, read server
source code or observe runtime traffic, so logging and telemetry (MCP08) and context
isolation between sessions (MCP10) need a separate review. Treat findings as input for
a human reviewer, not as a verdict.

## Roadmap

- [ ] Live mode: connect to stdio / Streamable HTTP servers with the official MCP SDK and
      fetch `tools/list`, `prompts/list` and `resources/list` directly
- [ ] Auto-discovery of client configs on a workstation (shadow MCP inventory)
- [ ] Optional LLM-assisted semantic review of tool descriptions with Claude, to catch
      poisoning that does not match fixed patterns
- [ ] Cross-server "toxic flow" analysis (untrusted input + private data + outbound channel)
- [ ] SARIF output for GitHub code scanning
- [ ] Report in Spanish

## Development

```bash
pip install -e ".[dev]"
pytest
```

## Author

Renzo Di Guglielmo · [LinkedIn](https://www.linkedin.com/in/renzo-di-guglielmo-ciberseguridad-redes/)

MIT licence. The OWASP MCP Top 10 names are used for reference under CC BY-NC-SA 4.0.
