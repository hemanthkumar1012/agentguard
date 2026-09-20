from app.audit import AuditLedger
from app.domain import ActionRequest, Decision
from app.gateway import ToolGateway
from app.identity import AgentRegistry


def test_unknown_agent_is_blocked_and_audited():
    gateway = ToolGateway(AgentRegistry(), AuditLedger())
    result = gateway.authorize(
        ActionRequest(agent_id="missing", action="send_email", target="example.com")
    )
    assert result.decision.decision == Decision.BLOCK
    assert "Unknown agent" in result.decision.reason


def test_missing_permission_is_blocked():
    registry = AgentRegistry()
    agent = registry.register("support", "team", permissions={"read_customer"})
    gateway = ToolGateway(registry, AuditLedger())
    result = gateway.authorize(
        ActionRequest(agent_id=agent.agent_id, action="export_data", target="crm")
    )
    assert result.decision.decision == Decision.BLOCK


def test_authorized_action_reaches_policy_engine():
    registry = AgentRegistry()
    agent = registry.register("support", "team", permissions={"send_email"})
    audit = AuditLedger()
    gateway = ToolGateway(registry, audit)
    result = gateway.authorize(
        ActionRequest(agent_id=agent.agent_id, action="send_email", target="company.com")
    )
    assert result.decision.decision == Decision.ALLOW
    assert len(audit.list_events()) == 1
    assert audit.list_events()[0]["event_id"] == result.event_id
