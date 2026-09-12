from fastapi.testclient import TestClient

from app.main import app
from app.services import agent_registry


client = TestClient(app)


def test_health_endpoint() -> None:
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "agentguard-api"}


def test_decision_endpoint_uses_runtime_enforcement() -> None:
    agent = agent_registry.register(
        "decision-test",
        "security",
        permissions={"send_email"},
    )

    response = client.post(
        "/api/v1/decisions",
        json={
            "agent_id": agent.agent_id,
            "action": "send_email",
            "target": "customer@example.com",
            "data_classification": "public",
            "risk_score": 10,
        },
    )

    assert response.status_code == 200
    assert response.json()["decision"] == "allow"
    assert response.json()["agent_id"] == agent.agent_id
    agent_registry._agents.pop(agent.agent_id, None)


def test_decision_endpoint_fails_closed_for_unknown_agent() -> None:
    response = client.post(
        "/api/v1/decisions",
        json={
            "agent_id": "unknown-agent",
            "action": "send_email",
            "target": "customer@example.com",
            "data_classification": "public",
            "risk_score": 0,
        },
    )

    assert response.status_code == 200
    assert response.json()["decision"] == "block"
    assert response.json()["reason"] == "Unknown agent identity."
