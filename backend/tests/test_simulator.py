from app.domain import Decision
from app.services import agent_registry
from app.simulator import RedTeamSimulator


def test_red_team_scenarios_are_blocked_without_execution():
    agent = agent_registry.register(
        "support-demo",
        "security-tests",
        permissions={"send_email"},
        environment="test",
    )
    results = RedTeamSimulator().run(agent.agent_id)
    assert len(results) == 3
    assert all(item["expected"] == Decision.BLOCK.value for item in results)
    assert all(item["passed"] for item in results)
    agent_registry._agents.pop(agent.agent_id, None)
