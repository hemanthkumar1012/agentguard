from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.data_inspector import inspect
from app.domain import ActionRequest
from app.risk import assess
from app.services import credential_broker

router = APIRouter(prefix="/security", tags=["security"])


class CredentialRequest(BaseModel):
    agent_id: str = Field(min_length=1)
    tool: str = Field(min_length=1)
    scopes: set[str] = Field(min_length=1)
    ttl_seconds: int = Field(default=300, ge=30, le=3600)


class InspectionRequest(BaseModel):
    text: str = Field(min_length=1, max_length=100_000)


@router.post("/risk")
def calculate_risk(request: ActionRequest):
    return assess(request)


@router.post("/inspect")
def inspect_data(request: InspectionRequest):
    return inspect(request.text)


@router.post("/credentials")
def issue_credential(request: CredentialRequest):
    credential = credential_broker.issue(
        request.agent_id, request.tool, request.scopes, request.ttl_seconds
    )
    return {
        "credential_id": credential.credential_id,
        "agent_id": credential.agent_id,
        "tool": credential.tool,
        "scopes": sorted(credential.scopes),
        "token": credential.token,
        "expires_at": credential.expires_at,
    }


@router.post("/credentials/{credential_id}/revoke")
def revoke_credential(credential_id: str):
    return {
        "credential_id": credential_id,
        "revoked": credential_broker.revoke(credential_id),
    }
