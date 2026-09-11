from dataclasses import dataclass

from app.domain import ActionRequest, Decision
from app.services import tool_gateway
from app.tool_runtime import ToolRuntime


@dataclass(frozen=True)
class MCPToolRequest:
    agent_id: str
    tool: str
    action: str
    target: str
    arguments: dict
    credential_id: str | None = None
    content: str | None = None
    data_classification: str = "public"
    risk_score: float = 0


class MCPGateway:
    """MCP-shaped adapter: authorize first, execute second."""

    def __init__(self, runtime: ToolRuntime) -> None:
        self.runtime = runtime

    def call(self, request: MCPToolRequest) -> dict:
        decision = tool_gateway.authorize(
            ActionRequest(
                agent_id=request.agent_id,
                action=request.action,
                target=request.target,
                data_classification=request.data_classification,
                risk_score=request.risk_score,
                content=request.content,
                tool=request.tool,
                credential_id=request.credential_id,
            )
        )
        if decision.decision.decision != Decision.ALLOW:
            return {"executed": False, "decision": decision.decision.model_dump(mode="json"), "event_id": decision.event_id}
        result = self.runtime.execute(request.agent_id, request.tool, request.action, request.arguments)
        return {"executed": True, "decision": decision.decision.model_dump(mode="json"), "event_id": decision.event_id, "result": result.output}
