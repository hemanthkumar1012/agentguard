from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_health_endpoint() -> None:
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "agentguard-api"}


def test_decision_endpoint() -> None:
    response = client.post(
        "/api/v1/decisions",
        json={
            "agent_id": "support-agent",
            "action": "send_email",
            "target": "customer@example.com",
            "data_classification": "public",
            "risk_score": 10,
        },
    )
    assert response.status_code == 200
    assert response.json()["decision"] == "allow"
