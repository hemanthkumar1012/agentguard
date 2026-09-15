from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.audit import AuditLedger
from app.domain import ActionRequest, Decision
from app.services import audit_ledger, tool_gateway
from app.tool_runtime import ToolRuntime, echo_tool

router = APIRouter(prefix="/tools", tags=["tools"])

runtime = ToolRuntime()
runtime.register("demo", "echo", echo_tool)


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
    payload: dict = Field(default_factory=dict)


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
        )
    )

    if authorization.decision.decision != Decision.ALLOW:
        return {"executed": False, "decision": authorization.decision, "event_id": authorization.event_id}

    try:
        result = runtime.execute(request.agent_id, request.tool, request.action, request.payload)
    except KeyError as exc:
        audit_ledger.append(
            agent_id=request.agent_id,
            action=request.action,
            target=request.target,
            decision=Decision.BLOCK.value,
            risk_score=authorization.decision.risk_score,
            reason="Requested tool handler is not registered.",
            tool=request.tool,
            credential_id=request.credential_id,
            correlation_id=request.correlation_id,
            policy_version=authorization.decision.model_dump().get("policy_version", ""),
            event_type="tool.execution.error",
        )
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        audit_ledger.append(
            agent_id=request.agent_id,
            action=request.action,
            target=request.target,
            decision="execution_error",
            risk_score=authorization.decision.risk_score,
            reason="Authorized tool execution failed.",
            tool=request.tool,
            credential_id=request.credential_id,
            correlation_id=request.correlation_id,
            event_type="tool.execution.error",
        )
        raise HTTPException(status_code=502, detail="Tool execution failed") from exc

    return {
        "executed": True,
        "decision": authorization.decision,
        "event_id": authorization.event_id,
        "tool_result": result.output,
    }
