"""Static checks over MCP server configs and tool definitions."""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Iterator
from urllib.parse import parse_qsl, urlparse

from .models import Finding, Server, Severity, Tool
from .rules import RULES

# --------------------------------------------------------------------------- helpers


def make_finding(
    rule_id: str,
    server: str,
    location: str,
    evidence: str,
    tool: str | None = None,
    severity: Severity | None = None,
) -> Finding:
    rule = RULES[rule_id]
    return Finding(
        rule_id=rule.id,
        title=rule.title,
        severity=severity if severity is not None else rule.severity,
        server=server,
        tool=tool,
        location=location,
        evidence=evidence,
        recommendation=rule.recommendation,
        owasp=list(rule.owasp),
        iso27001=list(rule.iso27001),
    )


def mask(value: str) -> str:
    """Never print a full secret in a report."""
    value = value.strip()
    if len(value) <= 6:
        return "****"
    return f"{value[:4]}****({len(value)} chars)"


def snippet(text: str, start: int, end: int, width: int = 40) -> str:
    left = max(0, start - width)
    right = min(len(text), end + width)
    out = text[left:right].replace("\n", " ")
    out = re.sub(r"\s+", " ", out).strip()
    return ("…" if left else "") + out + ("…" if right < len(text) else "")


def is_placeholder(value: str) -> bool:
    v = value.strip()
    return (
        not v
        or "${" in v
        or v.startswith("$")
        or v.startswith("env:")
        or "{{" in v
        or (v.startswith("<") and v.endswith(">"))
        or v.upper() in {"CHANGEME", "REDACTED", "XXX", "YOUR_TOKEN_HERE"}
    )


def tool_texts(tool: Tool) -> Iterator[tuple[str, str]]:
    """Yield (location, text) for every human/model-readable string in a tool."""
    yield f"tool:{tool.name}.description", tool.description

    def walk(schema: object, path: str) -> Iterator[tuple[str, str]]:
        if not isinstance(schema, dict):
            return
        for key in ("description", "title"):
            if isinstance(schema.get(key), str):
                yield f"{path}.{key}", schema[key]
        for prop, sub in (schema.get("properties") or {}).items():
            yield from walk(sub, f"{path}.properties.{prop}")
        if isinstance(schema.get("items"), dict):
            yield from walk(schema["items"], f"{path}.items")

    yield from walk(tool.input_schema, f"tool:{tool.name}.inputSchema")


# --------------------------------------------------------------------------- BQ-001 secrets

KNOWN_TOKEN_PATTERNS = {
    "GitHub token": re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{40,}\b"),
    "Anthropic API key": re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}"),
    "OpenAI-style API key": re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9]{20,}"),
    "AWS access key ID": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "Slack token": re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}"),
    "GitLab token": re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}"),
    "Google API key": re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    "Private key block": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
}
SECRET_NAME = re.compile(
    r"(TOKEN|SECRET|PASSWORD|PASSWD|PWD|API[_-]?KEY|ACCESS[_-]?KEY|PRIVATE[_-]?KEY|CLIENT[_-]?SECRET|AUTH)",
    re.IGNORECASE,
)
SECRET_FLAG = re.compile(r"^--?(token|api[-_]?key|password|secret|access[-_]?key)(=(.+))?$", re.IGNORECASE)


def _known_token(value: str) -> str | None:
    for label, pattern in KNOWN_TOKEN_PATTERNS.items():
        if pattern.search(value):
            return label
    return None


def check_secrets(server: Server) -> list[Finding]:
    findings: list[Finding] = []

    def literal(location: str, name: str, value: str) -> None:
        if is_placeholder(value):
            return
        label = _known_token(value)
        if label:
            findings.append(make_finding(
                "BQ-001", server.name, location,
                f"{label} in '{name}': {mask(value)}", severity=Severity.CRITICAL))
        elif SECRET_NAME.search(name) and len(value.strip()) >= 8:
            findings.append(make_finding(
                "BQ-001", server.name, location, f"Literal value in '{name}': {mask(value)}"))

    for key, value in server.env.items():
        literal(f"config:{server.name}.env.{key}", key, value)
    for key, value in server.headers.items():
        literal(f"config:{server.name}.headers.{key}", key, value)

    args = server.args
    for i, arg in enumerate(args):
        flag = SECRET_FLAG.match(arg)
        if flag:
            value = flag.group(3) or (args[i + 1] if i + 1 < len(args) else "")
            literal(f"config:{server.name}.args[{i}]", flag.group(1), value)
        elif _known_token(arg):
            literal(f"config:{server.name}.args[{i}]", "argument", arg)

    if server.url:
        for key, value in parse_qsl(urlparse(server.url).query):
            literal(f"config:{server.name}.url?{key}", key, value)
    return findings


# --------------------------------------------------------------------------- BQ-002 pinning

EXACT_VERSION = re.compile(r"^v?\d+\.\d+\.\d+([.\-+][0-9A-Za-z.\-]+)?$")
DOCKER_VALUE_FLAGS = {
    "-e", "--env", "-v", "--volume", "-p", "--publish", "--name", "--network", "-w",
    "--workdir", "--mount", "-u", "--user", "--env-file", "--entrypoint", "-l", "--label",
}


def _first_positional(args: list[str]) -> tuple[int, str] | None:
    for i, a in enumerate(args):
        if not a.startswith("-"):
            return i, a
    return None


def _npm_version(spec: str) -> str | None:
    body = spec[1:] if spec.startswith("@") else spec
    if "@" not in body:
        return None
    return body.rsplit("@", 1)[1]


def _python_version(spec: str) -> str | None:
    if "==" in spec:
        return spec.split("==", 1)[1]
    if "@" in spec and not spec.startswith(("git+", "http")):
        return spec.split("@", 1)[1]
    return None


def _docker_image(args: list[str]) -> str | None:
    if "run" not in args:
        return None
    rest = args[args.index("run") + 1:]
    skip = False
    for a in rest:
        if skip:
            skip = False
            continue
        if a.startswith("-"):
            if a in DOCKER_VALUE_FLAGS:
                skip = True
            continue
        return a
    return None


def check_pinning(server: Server) -> list[Finding]:
    if not server.command:
        return []
    cmd = server.command.rsplit("/", 1)[-1].lower()
    args = list(server.args)
    spec: str | None = None
    version: str | None = None
    kind = ""

    if cmd in {"npx", "bunx"} or (cmd in {"pnpm", "yarn"} and args[:1] == ["dlx"]):
        args = args[1:] if cmd in {"pnpm", "yarn"} else args
        pos = _first_positional(args)
        if pos:
            spec = pos[1]
            version, kind = _npm_version(spec), "npm package"
    elif cmd in {"uvx", "pipx"}:
        if cmd == "pipx" and args[:1] == ["run"]:
            args = args[1:]
        if "--from" in args and args.index("--from") + 1 < len(args):
            spec = args[args.index("--from") + 1]
        else:
            pos = _first_positional(args)
            spec = pos[1] if pos else None
        if spec:
            version, kind = _python_version(spec), "Python package"
    elif cmd in {"docker", "podman"}:
        spec = _docker_image(args)
        if spec:
            kind = "container image"
            if "@sha256:" in spec:
                return []
            last = spec.rsplit("/", 1)[-1]
            version = last.split(":", 1)[1] if ":" in last else None
            if version and version != "latest":
                return []  # tagged; digest pinning is still preferred but not flagged

    if not spec or not kind:
        return []
    if kind != "container image" and version and EXACT_VERSION.match(version):
        return []
    detail = f"no version" if not version else f"floating version '{version}'"
    auto = " (auto-install with -y)" if "-y" in server.args or "--yes" in server.args else ""
    return [make_finding(
        "BQ-002", server.name, f"config:{server.name}.args",
        f"{kind} '{spec}' runs with {detail}{auto}")]


# --------------------------------------------------------------------------- BQ-003/004 transport

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
AUTH_HEADERS = re.compile(r"^(authorization|x-api-key|api-key|x-auth-token|cookie)$", re.IGNORECASE)


def check_transport(server: Server) -> list[Finding]:
    if not server.url:
        return []
    parsed = urlparse(server.url)
    host = (parsed.hostname or "").lower()
    if host in LOCAL_HOSTS:
        return []
    findings = []
    if parsed.scheme == "http":
        findings.append(make_finding(
            "BQ-003", server.name, f"config:{server.name}.url", f"Endpoint: {server.url}"))
    has_auth = any(AUTH_HEADERS.match(k) for k in server.headers) or any(
        SECRET_NAME.search(k) for k, _ in parse_qsl(parsed.query))
    if not has_auth:
        findings.append(make_finding(
            "BQ-004", server.name, f"config:{server.name}.headers",
            f"No credential configured for remote endpoint {host}"))
    return findings


# --------------------------------------------------------------------------- BQ-005 scope

BROAD_PATHS = re.compile(
    r"^(/|~|~/|\$HOME|\$\{HOME\}|%USERPROFILE%|[A-Za-z]:\\?|/home/[^/]+/?|/Users/[^/]+/?|/root/?)$"
)


def check_scope(server: Server) -> list[Finding]:
    findings = []
    for i, arg in enumerate(server.args):
        candidates = [arg]
        if ":" in arg and not re.match(r"^[A-Za-z]:\\", arg) and "://" not in arg:
            candidates.append(arg.split(":", 1)[0])  # docker -v SRC:DST
        if "=" in arg:
            candidates.append(arg.split("=", 1)[1])
        if any(BROAD_PATHS.match(c.strip()) for c in candidates):
            findings.append(make_finding(
                "BQ-005", server.name, f"config:{server.name}.args[{i}]",
                f"Server is granted access to '{arg}'"))
    return findings


# --------------------------------------------------------------------------- tool checks

EXEC_NAME = re.compile(
    r"^(?:.*_)?(?:exec|execute|run|eval)_?(?:command|cmd|shell|script|code|bash|terminal)s?$"
    r"|^(?:shell|bash|terminal|exec|eval|run_shell)$",
    re.IGNORECASE,
)
EXEC_DESC = re.compile(
    r"\b(execute|run)s?\s+(any|arbitrary)?\s*(shell|terminal|system|bash)?\s*commands?\b"
    r"|\barbitrary (code|commands?)\b",
    re.IGNORECASE,
)

POISON_PATTERNS = [
    (r"ignore (all |any )?(previous|prior|above|earlier) (instructions|messages|rules)", "override of prior instructions"),
    (r"\b(do not|don't|never) (tell|inform|mention|reveal|show|notify|alert)\b[^.]{0,40}\buser\b", "concealment from the user"),
    (r"\bwithout (telling|informing|notifying|asking|alerting) the user\b", "concealment from the user"),
    (r"\bbefore (using|calling|invoking|running) (this|any other|any|other) tools?\b", "pre-condition on other tool use"),
    (r"\byou (must|should|need to) (always |first |also )*(read|send|include|call|forward|attach|pass|upload)\b", "imperative directed at the model"),
    (r"<\s*/?\s*(important|system|instructions?|secret|hidden)\s*>", "pseudo-system tag"),
    (r"\b(secretly|silently|covertly|quietly)\b", "covert behaviour"),
    (r"\byou are now\b|\bnew instructions?\b|\bsystem prompt\b", "role or prompt override"),
    (r"\b(note|message|instructions?) (for|to) the (assistant|model|ai|agent|llm)\b", "message addressed to the model"),
]
POISON_RE = [(re.compile(p, re.IGNORECASE), label) for p, label in POISON_PATTERNS]

INVISIBLE = re.compile("[​-‏‪-‮⁠-⁤⁦-⁩﻿\U000e0000-\U000e007f]")
HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
PADDING = re.compile(r"[ \t]{40,}|\n{8,}")

SENSITIVE = re.compile(
    r"~/\.ssh|\bid_(rsa|ed25519|ecdsa)\b|\.ssh/|(^|[\s/'\"`])\.env\b|\.aws/credentials|\.npmrc|\.netrc"
    r"|\.git-credentials|/etc/(passwd|shadow)|mcp\.json|claude_desktop_config|private key"
    r"|\b(seed|recovery) phrase\b|\bwallet\.dat\b|\.kube/config",
    re.IGNORECASE,
)

HIGH_RISK_PARAMS = {
    "command": Severity.MEDIUM, "cmd": Severity.MEDIUM, "shell": Severity.MEDIUM,
    "script": Severity.MEDIUM, "code": Severity.MEDIUM, "sql": Severity.MEDIUM,
    "query_sql": Severity.MEDIUM, "expression": Severity.MEDIUM,
    "path": Severity.LOW, "file": Severity.LOW, "filepath": Severity.LOW,
    "file_path": Severity.LOW, "filename": Severity.LOW, "directory": Severity.LOW,
    "url": Severity.LOW, "uri": Severity.LOW, "endpoint": Severity.LOW, "host": Severity.LOW,
}
CONSTRAINT_KEYS = {"enum", "const", "pattern", "format", "maxLength"}


def check_tool(server: Server, tool: Tool) -> list[Finding]:
    findings: list[Finding] = []
    s, t = server.name, tool.name

    if EXEC_NAME.match(t) or EXEC_DESC.search(tool.description):
        findings.append(make_finding(
            "BQ-006", s, f"tool:{t}", f"Tool '{t}' exposes command/code execution", tool=t))

    for location, text in tool_texts(tool):
        if not text:
            continue
        hits = []
        for pattern, label in POISON_RE:
            m = pattern.search(text)
            if m:
                hits.append((label, m))
        if hits:
            labels = sorted({label for label, _ in hits})
            first = hits[0][1]
            findings.append(make_finding(
                "BQ-007", s, location,
                f"{', '.join(labels)}: \"{snippet(text, first.start(), first.end())}\"", tool=t))

        hidden = []
        if INVISIBLE.search(text):
            n = len(INVISIBLE.findall(text))
            hidden.append(f"{n} invisible Unicode character(s)")
        if HTML_COMMENT.search(text):
            hidden.append("HTML comment")
        if PADDING.search(text):
            hidden.append("whitespace padding that can push text out of view")
        if hidden:
            findings.append(make_finding("BQ-008", s, location, "; ".join(hidden), tool=t))

        m = SENSITIVE.search(text)
        if m:
            findings.append(make_finding(
                "BQ-009", s, location,
                f"References '{m.group(0).strip()}': \"{snippet(text, m.start(), m.end())}\"",
                tool=t))

    props = (tool.input_schema or {}).get("properties") or {}
    for prop, schema in props.items():
        severity = HIGH_RISK_PARAMS.get(prop.lower())
        if severity is None or not isinstance(schema, dict):
            continue
        if schema.get("type", "string") != "string":
            continue
        if CONSTRAINT_KEYS & set(schema):
            continue
        findings.append(make_finding(
            "BQ-012", s, f"tool:{t}.inputSchema.properties.{prop}",
            f"Free-form string parameter '{prop}' with no enum, pattern, format or maxLength",
            tool=t, severity=severity))
    return findings


def check_cross_server(servers: list[Server]) -> list[Finding]:
    findings: list[Finding] = []
    owners: dict[str, list[str]] = defaultdict(list)
    for server in servers:
        for tool in server.tools:
            owners[tool.name].append(server.name)

    for name, srv_names in owners.items():
        unique = sorted(set(srv_names))
        if len(unique) > 1:
            findings.append(make_finding(
                "BQ-011", unique[0], f"tool:{name}",
                f"Tool '{name}' is defined by servers: {', '.join(unique)}", tool=name))

    for server in servers:
        foreign = {n for n, srvs in owners.items() if server.name not in srvs and len(n) >= 4}
        for tool in server.tools:
            for location, text in tool_texts(tool):
                for other in sorted(foreign):
                    m = re.search(rf"(?<![\w-]){re.escape(other)}(?![\w-])", text)
                    if m:
                        theirs = ", ".join(sorted(set(owners[other])))
                        findings.append(make_finding(
                            "BQ-010", server.name, location,
                            f"Mentions '{other}' (owned by {theirs}): "
                            f"\"{snippet(text, m.start(), m.end())}\"",
                            tool=tool.name))
    return findings


SERVER_CHECKS = (check_secrets, check_pinning, check_transport, check_scope)


def run_checks(servers: list[Server]) -> list[Finding]:
    findings: list[Finding] = []
    for server in servers:
        for check in SERVER_CHECKS:
            findings.extend(check(server))
        for tool in server.tools:
            findings.extend(check_tool(server, tool))
    findings.extend(check_cross_server(servers))
    return findings
