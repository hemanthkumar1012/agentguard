from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.config import settings
from app.domain import ActionRequest, Decision
from app.services import audit_ledger, tool_gateway
from app.tool_runtime import ToolRuntime, echo_tool
from app.mcp_remote import register_configured_servers

router = APIRouter(prefix="/tools", tags=["tools"])

runtime = ToolRuntime()
runtime.register("demo", "echo", echo_tool)
register_configured_servers(runtime)


class ToolExecutionRequest(BaseModel):
    agent_id: str = Field(min_length=1)
    tool: str = Field(min_length=1, max_length=100)
    action: str = Field(min_length=1, max_length=100)
    target: str = Field(min_length=1, max_length=500)
    data_classification: str = Field(default="public", min_length=1)
    risk_score: float = Field(default=0, ge=0, le=100)
    credential_id: str | None = Field(default=None, min_length=1, max_length=200)
    credential_token: str | None = Field(default=None, min_length=1, max_length=500)
    content: str | None = Field(default=None, max_length=100_000)
    correlation_id: str | None = Field(default=None, min_length=1, max_length=100)
    approval_id: str | None = Field(default=None, min_length=1, max_length=100)
    payload: dict = Field(default_factory=dict)


def record_execution_error(request: ToolExecutionRequest, risk_score: float, reason: str) -> None:
    audit_ledger.append(
        agent_id=request.agent_id,
        action=request.action,
        target=request.target,
        decision=Decision.BLOCK.value,
        risk_score=risk_score,
        reason=reason,
        tool=request.tool,
        credential_id=request.credential_id,
        correlation_id=request.correlation_id,
        policy_version=settings.policy_version,
        event_type="tool.execution.error",
    )


@router.post("/execute")
def execute_tool(request: ToolExecutionRequest):
    authorization = tool_gateway.authorize(
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
            approval_id=request.approval_id,
            execution_payload=request.payload,
        ),
        consume_approval=True,
    )

    if authorization.decision.decision != Decision.ALLOW:
        return {"executed": False, "decision": authorization.decision, "event_id": authorization.event_id}

    try:
        result = runtime.execute(request.agent_id, request.tool, request.action, request.payload)
    except KeyError as exc:
        record_execution_error(request, authorization.decision.risk_score, "Requested tool handler is not registered.")
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        record_execution_error(request, authorization.decision.risk_score, "Authorized tool execution failed.")
        raise HTTPException(status_code=502, detail="Tool execution failed") from exc

    return {
        "executed": True,
        "decision": authorization.decision,
        "event_id": authorization.event_id,
        "tool_result": result.output,
    }
