from app.domain import Decision
from app.services import agent_registry
from app.simulator import RedTeamSimulator


def test_red_team_scenarios_fail_safe_without_execution():
    # The agent holds the permissions the attacks use, so the policy itself is tested.
    # (With only "send_email", every scenario was blocked by the permission check and the
    # policy was never reached, which hid the payload weakness below.)
    agent = agent_registry.register(
        "support-demo",
        "security-tests",
        permissions={"send_email", "export_data"},
        environment="test",
    )
    try:
        results = {item["scenario_id"]: item for item in RedTeamSimulator().run(agent.agent_id)}
    finally:
        agent_registry._agents.pop(agent.agent_id, None)

    assert len(results) == 4
    assert all(item["passed"] for item in results.values()), results
    assert results["prompt-injection-pii-export"]["actual"] == Decision.BLOCK.value
    assert results["privilege-escalation"]["actual"] == Decision.BLOCK.value
    assert results["external-secret-exfiltration"]["actual"] == Decision.BLOCK.value


def test_secret_in_tool_payload_needs_human_approval():
    # Regression test for the weakness the simulator exposed on 2026-11-22.
    agent = agent_registry.register("mailer", "security-tests", permissions={"send_email"}, environment="test")
    try:
        results = {item["scenario_id"]: item for item in RedTeamSimulator().run(agent.agent_id)}
    finally:
        agent_registry._agents.pop(agent.agent_id, None)
    assert results["secret-in-tool-payload"]["actual"] == Decision.REQUIRE_APPROVAL.value
