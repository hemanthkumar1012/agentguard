from fastapi.testclient import TestClient

from app.main import app
from app.services import agent_registry


client = TestClient(app)


def test_approval_is_required_then_consumed_for_tool_execution():
    created = client.post(
        "/api/v1/agents",
        json={"name": "approval-agent", "owner": "security", "permissions": ["echo"]},
    )
    assert created.status_code == 201
    agent_id = created.json()["agent_id"]

    credential = client.post(
        "/api/v1/security/credentials",
        json={"agent_id": agent_id, "tool": "demo", "scopes": ["echo"]},
    )
    assert credential.status_code == 200
    credential_data = credential.json()

    request = {
        "agent_id": agent_id,
        "tool": "demo",
        "action": "echo",
        "target": "external-mail",
        "data_classification": "pii",
        "risk_score": 45,
        "credential_id": credential_data["credential_id"],
        "credential_token": credential_data["token"],
        "payload": {"message": "hello"},
    }

    pending = client.post("/api/v1/tools/execute", json=request)
    assert pending.status_code == 200
    assert pending.json()["executed"] is False
    assert pending.json()["decision"]["decision"] == "require_approval"
    approval_id = pending.json()["decision"]["approval_id"]

    approved = client.post(
        f"/api/v1/approvals/{approval_id}/decision",
        json={"approved": True, "decided_by": "operator"},
    )
    assert approved.status_code == 200
    assert approved.json()["status"] == "approved"

    request["approval_id"] = approval_id
    executed = client.post("/api/v1/tools/execute", json=request)
    assert executed.status_code == 200
    assert executed.json()["executed"] is True
    assert executed.json()["decision"]["decision"] == "allow"

    replayed = client.post("/api/v1/tools/execute", json=request)
    assert replayed.status_code == 200
    assert replayed.json()["executed"] is False
    assert replayed.json()["decision"]["decision"] == "block"
    assert "consumed" in replayed.json()["decision"]["reason"]

    agent_registry._agents.pop(agent_id, None)
