from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class ToolResult:
    tool: str
    action: str
    output: dict


ToolHandler = Callable[[str, str, dict], dict]


class ToolRuntime:
    """Minimal execution adapter used to demonstrate a real enforcement boundary.

    Production adapters can implement MCP or provider-specific clients behind
    this interface. Handlers receive already-authorized requests only.
    """

    def __init__(self) -> None:
        self._handlers: dict[tuple[str, str], ToolHandler] = {}

    def register(self, tool: str, action: str, handler: ToolHandler) -> None:
        self._handlers[(tool, action)] = handler

    def execute(self, agent_id: str, tool: str, action: str, payload: dict) -> ToolResult:
        handler = self._handlers.get((tool, action)) or self._handlers.get((tool, "*"))
        if handler is None:
            raise KeyError(f"No handler registered for {tool}:{action}")
        return ToolResult(tool=tool, action=action, output=handler(agent_id, action, payload))


def echo_tool(agent_id: str, action: str, payload: dict) -> dict:
    """Deterministic non-destructive tool for integration tests and demos."""
    return {"status": "executed", "agent_id": agent_id, "action": action, "payload": payload}
