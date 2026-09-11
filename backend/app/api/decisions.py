from fastapi import APIRouter

from app.audit import AuditLedger
from app.domain import ActionRequest, DecisionResponse
from app.policy import evaluate

router = APIRouter(prefix="/decisions", tags=["decisions"])
ledger = AuditLedger()


@router.post("", response_model=DecisionResponse)
def create_decision(request: ActionRequest) -> DecisionResponse:
    response = evaluate(request)
    ledger.append(
        agent_id=response.agent_id,
        action=response.action,
        target=response.target,
        decision=response.decision.value,
        risk_score=response.risk_score,
        reason=response.reason,
    )
    return response


@router.get("/audit")
def get_audit_events():
    return {"events": ledger.list_events()}
