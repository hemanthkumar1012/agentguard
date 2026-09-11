from fastapi.testclient import TestClient

from app.main import app
from app.services import agent_registry


client = TestClient(app)


def test_tool_request_requires_a_scoped_credential():
    created = client.post(
        "/api/v1/agents",
        json={
            "name": "credential-agent",
            "owner": "security",
            "environment": "test",
            "permissions": ["send_email"],
        },
    )
    assert created.status_code == 201
    agent_id = created.json()["agent_id"]

    denied = client.post(
        "/api/v1/gateway/authorize",
        json={
            "agent_id": agent_id,
            "action": "send_email",
            "target": "mail.example",
            "tool": "gmail",
        },
    )
    assert denied.status_code == 200
    assert denied.json()["decision"]["decision"] == "block"
    assert "scoped credential" in denied.json()["decision"]["reason"]

    credential = client.post(
        "/api/v1/security/credentials",
        json={
            "agent_id": agent_id,
            "tool": "gmail",
            "scopes": ["send_email"],
        },
    )
    assert credential.status_code == 200
    credential_id = credential.json()["credential_id"]

    allowed = client.post(
        "/api/v1/gateway/authorize",
        json={
            "agent_id": agent_id,
            "action": "send_email",
            "target": "mail.example",
            "tool": "gmail",
            "credential_id": credential_id,
            "content": "hello customer",
        },
    )
    assert allowed.status_code == 200
    assert allowed.json()["decision"]["decision"] == "allow"

    client.post(f"/api/v1/security/credentials/{credential_id}/revoke")
    revoked = client.post(
        "/api/v1/gateway/authorize",
        json={
            "agent_id": agent_id,
            "action": "send_email",
            "target": "mail.example",
            "tool": "gmail",
            "credential_id": credential_id,
        },
    )
    assert revoked.json()["decision"]["decision"] == "block"

    agent_registry._agents.pop(agent_id, None)


def test_credential_cannot_exceed_agent_permissions():
    created = client.post(
        "/api/v1/agents",
        json={
            "name": "least-privilege-agent",
            "owner": "security",
            "permissions": ["send_email"],
        },
    )
    agent_id = created.json()["agent_id"]

    credential = client.post(
        "/api/v1/security/credentials",
        json={
            "agent_id": agent_id,
            "tool": "gmail",
            "scopes": ["delete_files"],
        },
    )
    assert credential.status_code == 403
    agent_registry._agents.pop(agent_id, None)
