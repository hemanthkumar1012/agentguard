from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.agent_auth import AgentAuthorization
from app.services import agent_registry, persistence

router = APIRouter(prefix="/delegations", tags=["delegations"])
authorizer = AgentAuthorization(agent_registry, store=persistence)


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


@router.post("/revoke")
def revoke(request: CheckRequest):
    return {"revoked": authorizer.revoke(request.source_agent_id, request.target_agent_id)}


@router.post("/check")
def check(request: CheckRequest):
    return authorizer.check(request.source_agent_id, request.target_agent_id, request.action)
