from fastapi import APIRouter

from app.audit import AuditLedger
from app.domain import ActionRequest
from app.gateway import ToolGateway
from app.identity import AgentRegistry

router = APIRouter(prefix="/gateway", tags=["gateway"])
registry = AgentRegistry()
audit = AuditLedger()
gateway = ToolGateway(registry, audit)


@router.post("/authorize")
def authorize(request: ActionRequest):
    result = gateway.authorize(request)
    return {
        "decision": result.decision,
        "event_id": result.event_id,
    }


@router.get("/audit")
def list_audit_events():
    return {"events": audit.list_events()}
