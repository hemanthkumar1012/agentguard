from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.approvals import ApprovalStore

router = APIRouter(prefix="/approvals", tags=["approvals"])
store = ApprovalStore()


class CreateApprovalRequest(BaseModel):
    requested_by: str = Field(min_length=1, max_length=100)
    event_id: str | None = Field(default=None, max_length=100)


class DecideApprovalRequest(BaseModel):
    approved: bool
    decided_by: str = Field(min_length=1, max_length=100)
    note: str | None = Field(default=None, max_length=1000)


def serialize(item):
    return {
        "approval_id": item.approval_id,
        "event_id": item.event_id,
        "requested_by": item.requested_by,
        "status": item.status,
        "decision_note": item.decision_note,
        "expires_at": item.expires_at,
        "decided_by": item.decided_by,
        "decided_at": item.decided_at,
    }


@router.post("", status_code=201)
def create_approval(request: CreateApprovalRequest):
    return serialize(store.create(request.requested_by, request.event_id))


@router.get("")
def list_approvals():
    return {"approvals": [serialize(item) for item in store.list()]}


@router.get("/{approval_id}")
def get_approval(approval_id: str):
    item = store.get(approval_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Approval not found")
    return serialize(item)


@router.post("/{approval_id}/decision")
def decide_approval(approval_id: str, request: DecideApprovalRequest):
    try:
        return serialize(store.decide(approval_id, request.approved, request.decided_by, request.note))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
