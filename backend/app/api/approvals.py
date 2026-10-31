from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.services import approval_store

router = APIRouter(prefix="/approvals", tags=["approvals"])
class CreateApprovalRequest(BaseModel):
    requested_by: str = Field(min_length=1, max_length=100)
    event_id: str | None = Field(default=None, max_length=100)


class DecideApprovalRequest(BaseModel):
    approved: bool = False
    decided_by: str = Field(min_length=1, max_length=100)
    note: str | None = Field(default=None, max_length=1000)
    decided_by_role: str | None = Field(default=None, max_length=50)
    request_info: bool = Field(default=False, description="Ask the requester for more information instead of deciding.")


def serialize(item):
    return {
        "approval_id": item.approval_id,
        "event_id": item.event_id,
        "requested_by": item.requested_by,
        "request_fingerprint": item.request_fingerprint,
        "status": item.status,
        "decision_note": item.decision_note,
        "expires_at": item.expires_at,
        "decided_by": item.decided_by,
        "decided_at": item.decided_at,
        "consumed_at": item.consumed_at,
        "approver_role": item.approver_role,
        "context": item.context,
    }


@router.post("", status_code=201)
def create_approval(request: CreateApprovalRequest):
    return serialize(approval_store.create(request.requested_by, request.event_id))


@router.get("")
def list_approvals(status: str | None = None, approver_role: str | None = None):
    items = approval_store.list()
    if status:
        items = [i for i in items if i.status == status]
    if approver_role:
        items = [i for i in items if i.approver_role == approver_role]
    return {"approvals": [serialize(item) for item in items]}


@router.get("/{approval_id}")
def get_approval(approval_id: str):
    item = approval_store.get(approval_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Approval not found")
    return serialize(item)


@router.post("/{approval_id}/decision")
def decide_approval(approval_id: str, request: DecideApprovalRequest):
    try:
        return serialize(approval_store.decide(approval_id, request.approved, request.decided_by, request.note,
                                               decided_by_role=request.decided_by_role,
                                               request_info=request.request_info))
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
