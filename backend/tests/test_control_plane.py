from fastapi.testclient import TestClient

from app.main import app
from app.services import agent_registry, audit_ledger

client = TestClient(app)


def test_control_plane_snapshot_reports_security_metrics():
    agent = agent_registry.register(
        "metrics-agent", "security", environment="test", permissions={"send_email"}
    )
    audit_ledger.append(
        agent_id=agent.agent_id,
        action="send_email",
        target="internal-demo",
        decision="allow",
        risk_score=10,
        reason="test event",
    )

    response = client.get("/api/v1/control-plane/snapshot")
    assert response.status_code == 200
    body = response.json()
    assert body["agents"]["total"] >= 1
    assert body["decisions"]["allow"] >= 1
    assert body["risk"]["high_risk_events"] >= 0
    assert body["recent_events"][0]["agent_id"] == agent.agent_id

    agent_registry._agents.pop(agent.agent_id, None)
    audit_ledger._events.pop(0)
