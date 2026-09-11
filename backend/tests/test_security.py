from datetime import datetime, timedelta, timezone

from app.credentials import CredentialBroker
from app.data_inspector import inspect
from app.domain import ActionRequest
from app.risk import assess


def test_risk_engine_adds_contextual_factors():
    result = assess(ActionRequest(
        agent_id="agt_demo", action="export_data", target="external-crm",
        data_classification="pii", risk_score=50,
    ))
    assert result.score == 95
    assert "sensitive-data" in result.factors
    assert "high-impact-action" in result.factors
    assert "external-target" in result.factors


def test_data_inspector_detects_email_and_secret_marker():
    result = inspect("email alice@example.com password: hidden")
    assert result["contains_sensitive_data"] is True
    assert "email" in result["findings"]
    assert "secret_marker" in result["findings"]


def test_scoped_credential_is_bound_to_agent_tool_and_scope():
    broker = CredentialBroker(default_ttl_seconds=300)
    credential = broker.issue("agt_1", "gmail", {"send_email"})
    assert broker.validate(credential.credential_id, "agt_1", "gmail", "send_email")
    assert not broker.validate(credential.credential_id, "agt_2", "gmail", "send_email")
    assert not broker.validate(credential.credential_id, "agt_1", "drive", "send_email")
    assert not broker.validate(credential.credential_id, "agt_1", "gmail", "delete_files")


def test_expired_credential_is_invalid():
    broker = CredentialBroker()
    credential = broker.issue("agt_1", "gmail", {"send_email"}, ttl_seconds=30)
    expired = credential.__class__(
        **{**credential.__dict__, "expires_at": datetime.now(timezone.utc) - timedelta(seconds=1)}
    )
    broker._credentials[credential.credential_id] = expired
    assert not broker.validate(credential.credential_id, "agt_1", "gmail", "send_email")
