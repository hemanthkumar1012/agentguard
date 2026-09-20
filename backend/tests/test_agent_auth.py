import pytest

from app.agent_auth import AgentAuthorization
from app.identity import AgentRegistry


def test_agent_delegation_requires_explicit_scope():
    registry = AgentRegistry()
    source = registry.register("orchestrator", "platform", permissions={"send_email"})
    target = registry.register("mailer", "platform", permissions={"send_email"})
    auth = AgentAuthorization(registry)

    auth.grant(source.agent_id, target.agent_id, {"send_email"})
    result = auth.check(source.agent_id, target.agent_id, "send_email")

    assert result.allowed is True


def test_agent_delegation_cannot_exceed_source_permissions():
    registry = AgentRegistry()
    source = registry.register("orchestrator", "platform", permissions={"read_customer"})
    target = registry.register("mailer", "platform", permissions={"send_email"})
    auth = AgentAuthorization(registry)

    with pytest.raises(PermissionError):
        auth.grant(source.agent_id, target.agent_id, {"send_email"})
