from fastapi.testclient import TestClient

from app.main import app
from app.services import agent_registry


client = TestClient(app)


def test_registered_agent_can_authorize_through_shared_gateway():
    response = client.post(
        "/api/v1/agents",
        json={
            "name": "api-support-agent",
            "owner": "support",
            "environment": "test",
            "permissions": ["send_email"],
        },
    )
    assert response.status_code == 201
    agent_id = response.json()["agent_id"]

    decision = client.post(
        "/api/v1/gateway/authorize",
        json={
            "agent_id": agent_id,
            "action": "send_email",
            "target": "company.example",
            "data_classification": "public",
            "risk_score": 10,
        },
    )
    assert decision.status_code == 200
    assert decision.json()["decision"]["decision"] == "allow"

    audit = client.get("/api/v1/gateway/audit")
    assert audit.status_code == 200
    assert audit.json()["events"][0]["agent_id"] == agent_id

    # Keep the test process isolated for subsequent tests.
    agent_registry._agents.pop(agent_id, None)
