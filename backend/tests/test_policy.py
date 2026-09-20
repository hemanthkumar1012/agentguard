from app.domain import ActionRequest, Decision
from app.policy import evaluate


def test_low_risk_request_is_allowed() -> None:
    result = evaluate(
        ActionRequest(
            agent_id="support-agent",
            action="send_email",
            target="customer@example.com",
            data_classification="public",
            risk_score=20,
        )
    )
    assert result.decision == Decision.ALLOW


def test_sensitive_request_requires_approval() -> None:
    result = evaluate(
        ActionRequest(
            agent_id="support-agent",
            action="export_data",
            target="internal-crm",
            data_classification="pii",
            risk_score=65,
        )
    )
    assert result.decision == Decision.REQUIRE_APPROVAL


def test_critical_high_risk_action_is_blocked() -> None:
    result = evaluate(
        ActionRequest(
            agent_id="finance-agent",
            action="transfer_funds",
            target="bank-api",
            data_classification="financial",
            risk_score=90,
        )
    )
    assert result.decision == Decision.BLOCK
