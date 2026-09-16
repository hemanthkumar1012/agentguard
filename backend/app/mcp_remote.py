from __future__ import annotations

import json
import os
from dataclasses import dataclass
from itertools import count
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


@dataclass(frozen=True)
class MCPServer:
    name: str
    url: str
    token: str | None = None
    timeout_seconds: float = 10.0


def _configured_servers() -> dict[str, MCPServer]:
    tokens: dict[str, str] = {}
    for item in os.getenv("AGENTGUARD_MCP_TOKENS", "").split(","):
        name, separator, token = item.strip().partition("=")
        if separator and name and token:
            tokens[name] = token

    servers: dict[str, MCPServer] = {}
    for item in os.getenv("AGENTGUARD_MCP_SERVERS", "").split(","):
        name, separator, url = item.strip().partition("=")
        if not separator or not name or not url:
            continue
        parsed = urlparse(url)
        if parsed.scheme not in {"https", "http"} or not parsed.netloc:
            continue
        if parsed.scheme != "https" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
            continue
        servers[name] = MCPServer(name=name, url=url, token=tokens.get(name))
    return servers


class RemoteMCPClient:
    def __init__(self, server: MCPServer) -> None:
        self.server = server
        self._ids = count(1)

    def call_tool(self, agent_id: str, action: str, arguments: dict) -> dict:
        payload = {
            "jsonrpc": "2.0",
            "id": next(self._ids),
            "method": "tools/call",
            "params": {"name": action, "arguments": arguments, "agent_id": agent_id},
        }
        headers = {"content-type": "application/json", "accept": "application/json"}
        if self.server.token:
            headers["authorization"] = f"Bearer {self.server.token}"
        request = Request(self.server.url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
        try:
            with urlopen(request, timeout=self.server.timeout_seconds) as response:
                body = json.loads(response.read().decode("utf-8"))
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise RuntimeError("Configured MCP server request failed") from exc
        if body.get("error"):
            raise RuntimeError("Configured MCP server returned a JSON-RPC error")
        return body.get("result", {})


def register_configured_servers(runtime) -> None:
    for name, server in _configured_servers().items():
        client = RemoteMCPClient(server)
        runtime.register(name, "*", lambda agent_id, action, payload, client=client: client.call_tool(agent_id, action, payload))
