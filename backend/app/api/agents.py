from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.identity import AgentStatus
from app.services import agent_registry

router = APIRouter(prefix="/agents", tags=["agents"])


class RegisterAgentRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    owner: str = Field(min_length=1, max_length=100)
    environment: str = Field(default="development", min_length=1, max_length=50)
    permissions: set[str] = Field(default_factory=set)


def _serialize_agent(agent):
    return {
        "agent_id": agent.agent_id,
        "name": agent.name,
        "owner": agent.owner,
        "environment": agent.environment,
        "permissions": sorted(agent.permissions),
        "status": agent.status,
        "created_at": agent.created_at,
    }


@router.post("", status_code=201)
def register_agent(request: RegisterAgentRequest):
    agent = agent_registry.register(
        name=request.name,
        owner=request.owner,
        environment=request.environment,
        permissions=request.permissions,
    )
    return _serialize_agent(agent)


@router.get("/{agent_id}")
def get_agent(agent_id: str):
    agent = agent_registry.get(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    return _serialize_agent(agent)


@router.post("/{agent_id}/suspend")
def suspend_agent(agent_id: str):
    try:
        agent = agent_registry.suspend(agent_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Agent not found") from exc
    return {"agent_id": agent.agent_id, "status": AgentStatus.SUSPENDED}


@router.post("/{agent_id}/revoke")
def revoke_agent(agent_id: str):
    try:
        agent = agent_registry.revoke(agent_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Agent not found") from exc
    return {"agent_id": agent.agent_id, "status": AgentStatus.REVOKED}
