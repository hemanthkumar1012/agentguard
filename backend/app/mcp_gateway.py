from dataclasses import dataclass

from app.config import settings
from app.domain import ActionRequest, Decision
from app.services import audit_ledger, tool_gateway
from app.tool_runtime import ToolRuntime


@dataclass(frozen=True)
class MCPToolRequest:
    agent_id: str
    tool: str
    action: str
    target: str
    arguments: dict
    credential_id: str | None = None
    credential_token: str | None = None
    content: str | None = None
    data_classification: str = "public"
    risk_score: float = 0
    correlation_id: str | None = None


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
                credential_token=request.credential_token,
                correlation_id=request.correlation_id,
            )
        )
        if decision.decision.decision != Decision.ALLOW:
            return {"executed": False, "decision": decision.decision.model_dump(mode="json"), "event_id": decision.event_id}

        try:
            result = self.runtime.execute(request.agent_id, request.tool, request.action, request.arguments)
        except KeyError:
            self._record_execution_error(request, decision.decision.risk_score, "Requested tool handler is not registered.")
            raise
        except Exception as exc:
            self._record_execution_error(request, decision.decision.risk_score, "Authorized tool execution failed.")
            raise RuntimeError("Tool execution failed") from exc

        return {
            "executed": True,
            "decision": decision.decision.model_dump(mode="json"),
            "event_id": decision.event_id,
            "result": result.output,
        }

    @staticmethod
    def _record_execution_error(request: MCPToolRequest, risk_score: float, reason: str) -> None:
        audit_ledger.append(
            agent_id=request.agent_id,
            action=request.action,
            target=request.target,
            decision="execution_error",
            risk_score=risk_score,
            reason=reason,
            tool=request.tool,
            credential_id=request.credential_id,
            correlation_id=request.correlation_id,
            policy_version=settings.policy_version,
            event_type="tool.execution.error",
        )
