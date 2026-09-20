from app.identity import AgentRegistry, AgentStatus


def test_register_agent_creates_active_identity():
    registry = AgentRegistry()
    agent = registry.register(
        name="customer-support-agent",
        owner="demo-team",
        permissions={"read_customer", "send_email"},
    )

    assert agent.agent_id.startswith("agt_")
    assert agent.status == AgentStatus.ACTIVE
    assert agent.permissions == frozenset({"read_customer", "send_email"})


def test_suspend_agent_changes_status():
    registry = AgentRegistry()
    agent = registry.register(name="support", owner="demo-team")

    suspended = registry.suspend(agent.agent_id)

    assert suspended.status == AgentStatus.SUSPENDED
    assert registry.get(agent.agent_id).status == AgentStatus.SUSPENDED
