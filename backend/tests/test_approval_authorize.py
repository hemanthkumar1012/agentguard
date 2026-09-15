from fastapi.testclient import TestClient

from app.main import app
from app.services import agent_registry


client = TestClient(app)


def test_gateway_authorization_does_not_consume_approval_before_execution():
    agent = client.post(
        "/api/v1/agents",
        json={"name": "authorize-only-agent", "owner": "security", "permissions": ["echo"]},
    ).json()
    agent_id = agent["agent_id"]
    credential = client.post(
        "/api/v1/security/credentials",
        json={"agent_id": agent_id, "tool": "demo", "scopes": ["echo"]},
    ).json()
    request = {
        "agent_id": agent_id,
        "action": "echo",
        "target": "external-system",
        "data_classification": "pii",
        "risk_score": 45,
        "tool": "demo",
        "credential_id": credential["credential_id"],
        "credential_token": credential["token"],
    }

    pending = client.post("/api/v1/gateway/authorize", json=request).json()
    approval_id = pending["decision"]["approval_id"]
    client.post(f"/api/v1/approvals/{approval_id}/decision", json={"approved": True, "decided_by": "operator"})

    request["approval_id"] = approval_id
    checked = client.post("/api/v1/gateway/authorize", json=request)
    assert checked.status_code == 200
    assert checked.json()["decision"]["decision"] == "allow"

    approval = client.get(f"/api/v1/approvals/{approval_id}")
    assert approval.json()["status"] == "approved"
    assert approval.json()["consumed_at"] is None

    agent_registry._agents.pop(agent_id, None)
