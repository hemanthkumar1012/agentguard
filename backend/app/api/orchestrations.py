from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.services import orchestrator

router = APIRouter(prefix="/orchestrations", tags=["multi-agent"])


class OrchestrationRequest(BaseModel):
    message: str = Field(min_length=1, max_length=4000)
    tenant_id: str = Field(default="acmepay", max_length=100)
    user_id: str | None = Field(default=None, max_length=100)
    user_role: str = Field(default="customer", max_length=50)
    simulate_overreach: bool = Field(default=False, description="Make Billing try to issue a refund directly.")


@router.get("/agents")
def sub_agents():
    return {"agents": orchestrator.describe()}


@router.post("/run", status_code=201)
def run_orchestration(request: OrchestrationRequest):
    return orchestrator.run(request.message, request.tenant_id, request.user_id, request.user_role,
                            request.simulate_overreach).to_dict()
