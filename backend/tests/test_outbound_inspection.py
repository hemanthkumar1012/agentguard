from app.audit import AuditLedger
from app.data_inspector import MAX_PAYLOAD_DEPTH, inspect_outbound
from app.domain import ActionRequest, Decision
from app.gateway import SENSITIVE_OUTBOUND_REASON, ToolGateway
from app.identity import AgentRegistry


def make_gateway():
    registry = AgentRegistry()
    agent = registry.register("mailer", "team", permissions={"send_email"})
    return ToolGateway(registry, AuditLedger()), agent.agent_id


def request(agent_id, **overrides):
    base = dict(agent_id=agent_id, action="send_email", target="external-mail",
                data_classification="public", risk_score=10)
    base.update(overrides)
    return ActionRequest(**base)


def test_secret_in_payload_is_found_and_needs_approval():
    gateway, agent_id = make_gateway()
    result = gateway.authorize(request(agent_id, execution_payload={"body": "password: hunter2"}))
    assert result.decision.decision == Decision.REQUIRE_APPROVAL
    assert result.decision.reason == SENSITIVE_OUTBOUND_REASON
    assert "secret_marker" in result.decision.data_findings


def test_secret_in_content_also_needs_approval():
    gateway, agent_id = make_gateway()
    result = gateway.authorize(request(agent_id, content="api key sk_live_51Habcdefghijklmnop"))
    assert result.decision.decision == Decision.REQUIRE_APPROVAL


def test_clean_payload_is_still_allowed():
    gateway, agent_id = make_gateway()
    result = gateway.authorize(request(agent_id, execution_payload={"body": "Your parcel arrives on Friday."}))
    assert result.decision.decision == Decision.ALLOW


def test_nested_values_and_numbers_are_inspected():
    found = inspect_outbound(None, {"items": [{"note": "ok"}, {"card": 4111111111111111}]})
    assert "card_number" in found["findings"]
    found = inspect_outbound(None, {"meta": {"contacts": ["a.user@example.com"]}})
    assert "email" in found["findings"]


def test_payload_nested_too_deeply_is_reported_not_skipped():
    payload = current = {}
    for _ in range(MAX_PAYLOAD_DEPTH + 2):
        current["next"] = {}
        current = current["next"]
    assert "payload_too_deep" in inspect_outbound(None, payload)["findings"]
