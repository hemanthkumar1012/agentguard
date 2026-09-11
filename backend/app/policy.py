from app.domain import ActionRequest, Decision, DecisionResponse


HIGH_RISK_ACTIONS = {"delete", "transfer_funds", "export_data", "rotate_credentials"}
SENSITIVE_DATA = {"pii", "financial", "credentials", "secret"}


def evaluate(request: ActionRequest) -> DecisionResponse:
    if request.action in HIGH_RISK_ACTIONS and request.risk_score >= 80:
        decision = Decision.BLOCK
        reason = "High-risk action exceeds the runtime risk threshold."
    elif request.data_classification in SENSITIVE_DATA and request.risk_score >= 60:
        decision = Decision.REQUIRE_APPROVAL
        reason = "Sensitive data access requires human approval at this risk level."
    elif request.risk_score >= 70:
        decision = Decision.REQUIRE_APPROVAL
        reason = "Risk score requires human approval before execution."
    else:
        decision = Decision.ALLOW
        reason = "Request satisfies the initial runtime policy."

    return DecisionResponse(
        decision=decision,
        reason=reason,
        agent_id=request.agent_id,
        action=request.action,
        target=request.target,
        risk_score=request.risk_score,
    )
