from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.domain import ActionRequest, Decision
from app.services import tool_gateway
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
    content: str | None = Field(default=None, max_length=100_000)
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
        )
    )

    if authorization.decision.decision != Decision.ALLOW:
        return {
            "executed": False,
            "decision": authorization.decision,
            "event_id": authorization.event_id,
        }

    try:
        result = runtime.execute(
            request.agent_id, request.tool, request.action, request.payload
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    return {
        "executed": True,
        "decision": authorization.decision,
        "event_id": authorization.event_id,
        "tool_result": result.output,
    }
