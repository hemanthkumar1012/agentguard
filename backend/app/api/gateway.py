from fastapi import APIRouter

from app.domain import ActionRequest
from app.services import audit_ledger, tool_gateway

router = APIRouter(prefix="/gateway", tags=["gateway"])


@router.post("/authorize")
def authorize(request: ActionRequest):
    result = tool_gateway.authorize(request)
    return {
        "decision": result.decision,
        "event_id": result.event_id,
    }


@router.get("/audit")
def list_audit_events():
    return {"events": audit_ledger.list_events()}
