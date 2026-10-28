"""Self-contained HTML audit report: posture, OWASP MCP Top 10 coverage and the rug-pull diff.

Everything that comes from the audited servers (names, descriptions, schemas) is untrusted. It is escaped,
hidden characters are shown as highlighted escapes, and a Content-Security-Policy only lets the report's own
script run and blocks every remote load, so a payload that slipped past escaping still could not execute or
phone home.
"""
from __future__ import annotations

import base64
import difflib
import hashlib
import json
import re
from collections import Counter
from html import escape

from . import __version__
from .audit import AuditResult
from .baseline import Change
from .models import Finding, Severity
from .report import _HIDDEN, POSTURE, TARGET_DAYS
from .rules import ISO27001_A, OWASP_MCP_TOP10, OWASP_NOT_STATIC

SEVERITIES = sorted(Severity, reverse=True)

# Severity filter for the findings list. Its hash goes in the CSP: no other script can run.
SCRIPT = (
    "document.querySelectorAll('.filters button').forEach(function(b){b.addEventListener('click',function(){"
    "document.querySelectorAll('.filters button').forEach(function(x){x.setAttribute('aria-pressed',x===b)});"
    "var s=b.getAttribute('data-sev');"
    "document.querySelectorAll('#findings details').forEach(function(d){"
    "d.hidden=s!=='all'&&d.getAttribute('data-sev')!==s})})});"
)
CSP = ("default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; "
       "script-src 'sha256-" + base64.b64encode(hashlib.sha256(SCRIPT.encode()).digest()).decode() + "'")

CSS = """
:root{--bg:#f6f7f9;--card:#fff;--ink:#16202e;--muted:#5b6676;--line:#e2e6ec;--navy:#1d3557;
--critical:#8e1b3b;--high:#c0392b;--medium:#c48a12;--low:#4a6fa5;--info:#8a94a3;--ok:#2f855a;
--del-bg:#fde2e1;--del-ink:#8e1b1b;--ins-bg:#dcf3e3;--ins-ink:#1c5e36;--hid:#ffe08a}
@media (prefers-color-scheme:dark){:root{--bg:#0f141b;--card:#161d27;--ink:#e6ebf2;--muted:#9aa6b6;
--line:#273242;--navy:#8fb3e8;--critical:#d9467a;--del-bg:#4a1d22;--del-ink:#ffb4ae;--ins-bg:#173a26;
--ins-ink:#a6e3b8;--hid:#7a5c00}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:1120px;margin:0 auto;padding:28px 16px 64px}
header{border-bottom:3px solid var(--navy);padding-bottom:16px;margin-bottom:24px}
h1{font-size:28px;margin:0;color:var(--navy);letter-spacing:-.3px}
h2{font-size:19px;margin:36px 0 12px;color:var(--navy)}
h3{font-size:15px;margin:0}
.sub{color:var(--muted);margin-top:4px}
.meta{display:flex;flex-wrap:wrap;gap:6px 22px;margin-top:12px;font-size:13px;color:var(--muted)}
.meta b{color:var(--ink);font-weight:600}
code,.mono,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px}
code{overflow-wrap:anywhere}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600;color:#fff;white-space:nowrap}
.s-critical{background:var(--critical)}.s-high{background:var(--high)}.s-medium{background:var(--medium)}
.s-low{background:var(--low)}.s-info{background:var(--info)}
.posture{background:var(--card);border:1px solid var(--line);border-left:6px solid var(--info);border-radius:10px;padding:14px 18px}
.posture.critical{border-left-color:var(--critical)}.posture.high{border-left-color:var(--high)}
.posture.medium{border-left-color:var(--medium)}.posture.low{border-left-color:var(--low)}
.posture .v{font-size:20px;font-weight:700}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(105px,1fr));gap:12px;margin-top:12px}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.kpi .v{font-size:28px;font-weight:700;line-height:1.1}
.kpi .l{font-size:13px;color:var(--muted)}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px}
.stack{display:flex;height:16px;border-radius:8px;overflow:hidden;background:var(--line);margin:12px 0 6px}
.stack span{display:block;height:100%}
.legend{display:flex;flex-wrap:wrap;gap:12px;font-size:12.5px;color:var(--muted)}
.legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:5px;vertical-align:-1px}
.owasp{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px}
.cell{background:var(--card);border:1px solid var(--line);border-top:5px solid var(--ok);border-radius:10px;padding:10px 12px}
.cell.critical{border-top-color:var(--critical)}.cell.high{border-top-color:var(--high)}
.cell.medium{border-top-color:var(--medium)}.cell.low{border-top-color:var(--low)}
.cell.na{border-top-style:dashed;border-top-color:var(--info)}
.cell .id{font-weight:700;font-size:13px}.cell .n{float:right;font-size:22px;font-weight:700;line-height:1}
.cell .name{font-size:13px;margin-top:2px}.cell .note{font-size:12px;color:var(--muted);margin-top:4px}
.table-wrap{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:10px}
table{border-collapse:collapse;width:100%;font-size:13.5px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:middle}
th{font-size:12px;text-transform:uppercase;letter-spacing:.4px;color:var(--muted)}
tr:last-child td{border-bottom:none}
td.heat{text-align:center;font-weight:600;min-width:64px}
td.heat.zero{color:var(--muted);font-weight:400}
.heat.critical{background:color-mix(in srgb,var(--critical) var(--a),transparent)}
.heat.high{background:color-mix(in srgb,var(--high) var(--a),transparent)}
.heat.medium{background:color-mix(in srgb,var(--medium) var(--a),transparent)}
.heat.low{background:color-mix(in srgb,var(--low) var(--a),transparent)}
.heat.info{background:color-mix(in srgb,var(--info) var(--a),transparent)}
.recon{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.recon .kpi .items{font-size:12.5px;color:var(--muted);margin-top:4px}
.change{background:var(--card);border:1px solid var(--line);border-left:5px solid var(--high);border-radius:10px;padding:14px 16px;margin:12px 0}
.change .related{font-size:13px;color:var(--muted);margin:6px 0 10px}
.change .related a{color:var(--ink)}
.field{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px;font-weight:600;margin:12px 0 4px}
.diff{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.diff pre{margin:0;padding:10px 12px;border:1px solid var(--line);border-radius:8px;background:var(--bg);white-space:pre-wrap;overflow-wrap:anywhere;line-height:1.5}
.diff .lbl{font-size:12px;color:var(--muted);margin-bottom:4px}
del{background:var(--del-bg);color:var(--del-ink);text-decoration:line-through;border-radius:3px}
ins{background:var(--ins-bg);color:var(--ins-ink);text-decoration:none;border-radius:3px}
mark.hid{background:var(--hid);color:var(--ink);border-radius:3px;padding:0 2px;font-weight:700}
.filters{display:flex;gap:8px;flex-wrap:wrap;margin:6px 0 10px}
.filters button{border:1px solid var(--line);background:var(--card);color:var(--ink);padding:5px 12px;border-radius:999px;cursor:pointer;font:inherit;font-size:13px}
.filters button[aria-pressed=true]{background:var(--navy);color:var(--bg);border-color:var(--navy)}
details{background:var(--card);border:1px solid var(--line);border-radius:8px;margin:6px 0}
details:target{outline:2px solid var(--navy)}
summary{cursor:pointer;padding:9px 12px;display:flex;gap:10px;align-items:center;flex-wrap:wrap}
details .body{padding:0 14px 12px;font-size:14px}
details dl{display:grid;grid-template-columns:150px 1fr;gap:4px 12px;margin:0}
details dt{color:var(--muted);font-size:13px}details dd{margin:0}
.muted{color:var(--muted)}
footer{margin-top:40px;font-size:12.5px;color:var(--muted);border-top:1px solid var(--line);padding-top:12px}
@media (max-width:640px){.diff{grid-template-columns:1fr}details dl{grid-template-columns:1fr}}
"""


def _t(text) -> str:
    """Escape untrusted text; hidden characters become a visible, highlighted escape."""
    text = "" if text is None else str(text)
    out, pos = [], 0
    for m in _HIDDEN.finditer(text):
        c = ord(m.group())
        code = f"\\u{c:04x}" if c < 0x10000 else f"\\U{c:08x}"
        out.append(escape(text[pos:m.start()]))
        out.append(f'<mark class="hid" title="hidden character">{code}</mark>')
        pos = m.end()
    out.append(escape(text[pos:]))
    return "".join(out)


def _sev(s: Severity) -> str:
    return s.name.lower()


def _badge(s: Severity) -> str:
    return f'<span class="badge s-{_sev(s)}">{s.label}</span>'


_WORDS = re.compile(r"\s+|\S+")
_LINES = re.compile(r"[^\n]*\n|[^\n]+")


def _diff(before: str, after: str, by_line: bool = False) -> tuple[str, str]:
    """What was removed on the left, what was added on the right: by word for prose, by line for JSON."""
    token = _LINES if by_line else _WORDS
    a, b = token.findall(before), token.findall(after)
    left, right = [], []
    for op, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        old, new = _t("".join(a[i1:i2])), _t("".join(b[j1:j2]))
        if op == "equal":
            left.append(old)
            right.append(new)
            continue
        if old:
            left.append(f"<del>{old}</del>")
        if new:
            right.append(f"<ins>{new}</ins>")
    return "".join(left), "".join(right)


def _as_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True)


def _change(ch: Change, related: list[Finding]) -> str:
    what = f"<code>{_t(ch.server)}</code>" + (f" / <code>{_t(ch.tool)}</code>" if ch.tool else "")
    kind = "tool definition" if ch.tool else "server configuration"
    out = [f'<div class="change"><h3>{what} <span class="muted">· {kind} modified</span></h3>']
    if related:
        links = ", ".join(f'<a href="#{f.finding_id}">{f.finding_id}</a> {_badge(f.severity)} {escape(f.title)}'
                          for f in related)
        out.append(f'<div class="related">Findings on this component: {links}</div>')
    for key in sorted(set(ch.before) | set(ch.after)):
        if ch.before.get(key) == ch.after.get(key):
            continue
        old, new = ch.before.get(key), ch.after.get(key)
        prose = isinstance(old, (str, type(None))) and isinstance(new, (str, type(None)))
        left, right = _diff(_as_text(old), _as_text(new), by_line=not prose)
        out.append(f'<div class="field">{escape(key)}</div><div class="diff">'
                   f'<div><div class="lbl">Approved baseline</div><pre>{left or "<span class=muted>(none)</span>"}</pre></div>'
                   f'<div><div class="lbl">Current</div><pre>{right or "<span class=muted>(none)</span>"}</pre></div></div>')
    out.append("</div>")
    return "".join(out)


def _finding(f: Finding) -> str:
    where = f"<code>{_t(f.server)}</code>" + (f" / <code>{_t(f.tool)}</code>" if f.tool else "")
    days = TARGET_DAYS[f.severity]
    owasp = "<br>".join(f"{o} {escape(OWASP_MCP_TOP10[o])}" for o in f.owasp)
    iso = "<br>".join(f"A.{c} {escape(ISO27001_A.get(c, ''))}" for c in f.iso27001)
    return (f'<details id="{f.finding_id}" data-sev="{_sev(f.severity)}"><summary>'
            f'<span class="mono">{f.finding_id}</span>{_badge(f.severity)}{where}'
            f'<span>{escape(f.title)}</span></summary><div class="body"><dl>'
            f'<dt>Rule</dt><dd class="mono">{f.rule_id}</dd>'
            f'<dt>Location</dt><dd><code>{_t(f.location)}</code></dd>'
            f'<dt>Evidence</dt><dd><code>{_t(f.evidence)}</code></dd>'
            f'<dt>OWASP MCP</dt><dd>{owasp}</dd>'
            f'<dt>ISO 27001:2022</dt><dd>{iso}</dd>'
            f'<dt>Recommendation</dt><dd>{escape(f.recommendation)}</dd>'
            f'<dt>Target</dt><dd>{"-" if days is None else f"{days} days"}</dd>'
            f'</dl></div></details>')


def to_html(result: AuditResult) -> str:
    counts = result.count_by_severity()
    highest = result.highest
    total = len(result.findings)
    out: list[str] = []
    w = out.append

    w('<!doctype html><html lang="en"><head><meta charset="utf-8">'
      f'<meta http-equiv="Content-Security-Policy" content="{CSP}">'
      '<meta name="viewport" content="width=device-width, initial-scale=1">'
      f'<title>MCP Security Audit</title><style>{CSS}</style></head><body><div class="wrap">')

    w('<header><h1>MCP Security Audit</h1>'
      '<div class="sub">Static review of MCP servers and tool definitions, mapped to the OWASP MCP Top 10 '
      'and ISO/IEC 27001:2022 Annex A</div><div class="meta">')
    w(f"<span>Generated: <b>{escape(result.generated)}</b></span>")
    w(f"<span>By: <b>baqueano {__version__}</b></span>")
    for k, v in result.inputs.items():
        w(f"<span>{escape(k.capitalize())}: <code>{_t(v)}</code></span>")
    w("</div></header>")

    # Posture and severity distribution
    level = _sev(highest) if highest is not None else "info"
    posture = POSTURE[highest if highest is not None else Severity.INFO]
    head, _, tail = posture.partition(" - ")
    tail = tail[:1].upper() + tail[1:]
    w(f'<div class="posture {level}"><div class="muted">Overall risk posture</div>'
      f'<div class="v">{escape(head)}</div><div>{escape(tail)}</div></div>')
    w('<div class="kpis">')
    w(f'<div class="kpi"><div class="v">{total}</div><div class="l">Findings</div></div>')
    for s in SEVERITIES:
        w(f'<div class="kpi"><div class="v" style="color:var(--{_sev(s)})">{counts[s]}</div>'
          f'<div class="l">{s.label}</div></div>')
    w(f'<div class="kpi"><div class="v">{len(result.servers)}</div><div class="l">Servers · '
      f'{result.tool_count} tools</div></div></div>')
    if total:
        w('<div class="stack" role="img" aria-label="Findings by severity">')
        for s in SEVERITIES:
            if counts[s]:
                w(f'<span class="s-{_sev(s)}" style="width:{100 * counts[s] / total:.2f}%" '
                  f'title="{s.label}: {counts[s]}"></span>')
        w('</div><div class="legend">' + "".join(
            f'<span><i class="s-{_sev(s)}"></i>{s.label} {counts[s]}</span>' for s in SEVERITIES) + "</div>")

    # OWASP MCP Top 10 coverage
    w("<h2>OWASP MCP Top 10</h2><div class=\"owasp\">")
    by_owasp: dict[str, list[Finding]] = {code: [] for code in OWASP_MCP_TOP10}
    for f in result.findings:
        for o in f.owasp:
            by_owasp[o].append(f)
    for code, name in OWASP_MCP_TOP10.items():
        hits = by_owasp[code]
        note = OWASP_NOT_STATIC.get(code, "")
        cls = _sev(max(f.severity for f in hits)) if hits else ("na" if note else "")
        w(f'<div class="cell {cls}"><span class="n">{len(hits)}</span><div class="id">{code}</div>'
          f'<div class="name">{escape(name)}</div>'
          + (f'<div class="note">{escape(note)}</div>' if note else "") + "</div>")
    w('</div><div class="legend" style="margin-top:8px"><span>Top border: highest severity found.</span>'
      '<span><i style="background:var(--ok)"></i>No findings</span>'
      '<span><i style="border:1px dashed var(--info)"></i>Needs a runtime review</span></div>')

    # Server x severity heat map
    if result.findings:
        per = Counter((f.server, f.severity) for f in result.findings)
        servers = sorted({f.server for f in result.findings},
                         key=lambda s: [-per[(s, sev)] for sev in SEVERITIES] + [s])
        peak = max(per.values())
        w('<h2>Findings by server</h2><div class="table-wrap"><table><tr><th>Server</th>'
          + "".join(f"<th>{s.label}</th>" for s in SEVERITIES) + "<th>Total</th></tr>")
        for name in servers:
            row = [f"<td><code>{_t(name)}</code></td>"]
            for s in SEVERITIES:
                n = per[(name, s)]
                row.append(f'<td class="heat {_sev(s)}" style="--a:{20 + 60 * n / peak:.0f}%">{n}</td>' if n
                           else '<td class="heat zero">0</td>')
            row.append(f"<td><b>{sum(per[(name, s)] for s in SEVERITIES)}</b></td>")
            w("<tr>" + "".join(row) + "</tr>")
        w("</table></div>")

    # Baseline reconciliation, with the diff of every modified component
    rec = result.reconciliation
    if rec is not None:
        w("<h2>Baseline reconciliation</h2>")
        w(f'<p class="muted">{rec.total_compared} components compared against the approved baseline. '
          "A modified tool definition is how a rug pull shows up: the server keeps the name the reviewer "
          "approved and changes what it tells the model.</p><div class=\"recon\">")
        w(f'<div class="kpi"><div class="v" style="color:var(--ok)">{rec.unchanged}</div>'
          '<div class="l">Unchanged</div></div>')
        for label, items, color in (("Modified", rec.modified, "high"), ("Added", rec.added, "medium"),
                                    ("Removed", rec.removed, "low")):
            listed = "<br>".join(f"<code>{_t(i)}</code>" for i in items)
            w(f'<div class="kpi"><div class="v" style="color:var(--{color})">{len(items)}</div>'
              f'<div class="l">{label}</div><div class="items">{listed}</div></div>')
        w("</div>")
        for ch in rec.changes:
            related = [f for f in result.findings if f.server == ch.server and f.tool == ch.tool]
            w(_change(ch, related))

    # Findings
    if result.findings:
        w('<h2>Findings</h2><div class="filters"><button aria-pressed="true" data-sev="all">All '
          f"{total}</button>")
        for s in SEVERITIES:
            if counts[s]:
                w(f'<button aria-pressed="false" data-sev="{_sev(s)}">{s.label} {counts[s]}</button>')
        w('</div><div id="findings">' + "".join(_finding(f) for f in result.findings) + "</div>")

    w("<footer>Static review of the MCP client configuration and of the tool definitions the servers expose "
      "(<code>tools/list</code>). Rules are pattern-based and can produce false positives or miss obfuscated "
      "payloads; every finding should be confirmed by a reviewer before it is closed or accepted. The audit "
      "does not execute tools, inspect server source code or observe runtime behaviour. Text taken from the "
      "audited servers is escaped and hidden characters are highlighted; the page's Content-Security-Policy "
      "blocks remote loads and any script but its own severity filter.</footer>")
    w(f"</div><script>{SCRIPT}</script></body></html>")
    return "\n".join(out) + "\n"
