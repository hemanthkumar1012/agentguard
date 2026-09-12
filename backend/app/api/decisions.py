from fastapi import APIRouter

from app.domain import ActionRequest, DecisionResponse
from app.services import audit_ledger, tool_gateway

router = APIRouter(prefix="/decisions", tags=["decisions"])


@router.post("", response_model=DecisionResponse)
def create_decision(request: ActionRequest) -> DecisionResponse:
    """Evaluate a decision through the same enforcement boundary as tool execution."""
    return tool_gateway.authorize(request).decision


@router.get("/audit")
def get_audit_events():
    return {"events": audit_ledger.list_events()}
