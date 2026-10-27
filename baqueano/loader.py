"""Load MCP client configurations and tool manifests.

Supported config shapes:
  * {"mcpServers": {...}}  - Claude Desktop, Claude Code (.mcp.json), Cursor, Windsurf
  * {"servers": {...}}     - VS Code (.vscode/mcp.json)

Tool manifest: the `tools/list` result per server, in any of these shapes:
  * {"<server>": [tool, ...]}
  * {"<server>": {"tools": [tool, ...]}}
  * {"servers": {"<server>": {"tools": [...]}}}
"""
from __future__ import annotations

import json
from pathlib import Path

from .models import Server, Tool


class ConfigError(ValueError):
    pass


def _read_json(path: str | Path) -> dict:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"File not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Invalid JSON in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: expected a JSON object at the top level")
    return data


def parse_config(data: dict) -> list[Server]:
    entries = data.get("mcpServers", data.get("servers"))
    if not isinstance(entries, dict):
        raise ConfigError("No 'mcpServers' or 'servers' object found in config")

    servers = []
    for name, spec in entries.items():
        if not isinstance(spec, dict):
            raise ConfigError(f"Server '{name}' must be an object")
        url = spec.get("url") or spec.get("serverUrl")
        declared = str(spec.get("type", spec.get("transport", ""))).lower()
        if url:
            transport = "sse" if declared == "sse" else "http"
        else:
            transport = "stdio"
        servers.append(
            Server(
                name=name,
                transport=transport,
                command=spec.get("command"),
                args=[str(a) for a in spec.get("args", [])],
                env={str(k): str(v) for k, v in (spec.get("env") or {}).items()},
                url=url,
                headers={str(k): str(v) for k, v in (spec.get("headers") or {}).items()},
            )
        )
    return servers


def parse_tools(data: dict) -> dict[str, list[Tool]]:
    root = data.get("servers", data)
    result: dict[str, list[Tool]] = {}
    for server_name, entry in root.items():
        raw_tools = entry.get("tools", []) if isinstance(entry, dict) else entry
        if not isinstance(raw_tools, list):
            raise ConfigError(f"Tools for '{server_name}' must be a list")
        result[server_name] = [
            Tool(
                name=str(t.get("name", "")),
                description=str(t.get("description", "") or ""),
                input_schema=t.get("inputSchema", t.get("input_schema", {})) or {},
            )
            for t in raw_tools
        ]
    return result


def load(config_path: str | Path, tools_path: str | Path | None = None) -> list[Server]:
    servers = parse_config(_read_json(config_path))
    if tools_path:
        manifest = parse_tools(_read_json(tools_path))
        by_name = {s.name: s for s in servers}
        for server_name, tools in manifest.items():
            server = by_name.get(server_name)
            if server is None:
                # Tools for a server that is not in the config: keep them visible.
                server = Server(name=server_name, transport="unknown")
                servers.append(server)
                by_name[server_name] = server
            server.tools = tools
            server.tools_known = True
    return servers
