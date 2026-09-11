from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.api.tools import runtime
from app.mcp_gateway import MCPGateway, MCPToolRequest

router = APIRouter(prefix="/mcp", tags=["mcp"])
gateway = MCPGateway(runtime)


class MCPCallRequest(BaseModel):
    agent_id: str = Field(min_length=1)
    tool: str = Field(min_length=1, max_length=100)
    action: str = Field(min_length=1, max_length=100)
    target: str = Field(min_length=1, max_length=500)
    arguments: dict = Field(default_factory=dict)
    credential_id: str | None = Field(default=None, min_length=1, max_length=200)
    content: str | None = Field(default=None, max_length=100_000)
    data_classification: str = Field(default="public", min_length=1)
    risk_score: float = Field(default=0, ge=0, le=100)


@router.post("/call")
def call_tool(request: MCPCallRequest):
    try:
        return gateway.call(MCPToolRequest(**request.model_dump()))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
