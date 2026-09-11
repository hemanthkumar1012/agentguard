from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.agent_auth import AgentAuthorization
from app.services import agent_registry

router = APIRouter(prefix="/delegations", tags=["delegations"])
authorizer = AgentAuthorization(agent_registry)


class GrantRequest(BaseModel):
    source_agent_id: str = Field(min_length=1)
    target_agent_id: str = Field(min_length=1)
    scopes: set[str] = Field(min_length=1)


class CheckRequest(BaseModel):
    source_agent_id: str = Field(min_length=1)
    target_agent_id: str = Field(min_length=1)
    action: str = Field(min_length=1)


@router.post("/grant", status_code=204)
def grant(request: GrantRequest):
    try:
        authorizer.grant(request.source_agent_id, request.target_agent_id, request.scopes)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (ValueError, PermissionError) as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@router.post("/check")
def check(request: CheckRequest):
    return authorizer.check(request.source_agent_id, request.target_agent_id, request.action)
