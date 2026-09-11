from fastapi.testclient import TestClient

from app.main import app
from app.services import agent_registry, credential_broker


client = TestClient(app)


def test_credential_api_enforces_agent_permissions():
    response = client.post(
        "/api/v1/agents",
        json={
            "name": "credential-test-agent",
            "owner": "security",
            "environment": "test",
            "permissions": ["send_email"],
        },
    )
    assert response.status_code == 201
    agent_id = response.json()["agent_id"]

    denied = client.post(
        "/api/v1/security/credentials",
        json={
            "agent_id": agent_id,
            "tool": "gmail",
            "scopes": ["delete_files"],
        },
    )
    assert denied.status_code == 403

    issued = client.post(
        "/api/v1/security/credentials",
        json={
            "agent_id": agent_id,
            "tool": "gmail",
            "scopes": ["send_email"],
        },
    )
    assert issued.status_code == 200
    credential_id = issued.json()["credential_id"]

    blocked_tool_call = client.post(
        "/api/v1/gateway/authorize",
        json={
            "agent_id": agent_id,
            "action": "send_email",
            "target": "customer.example",
            "tool": "drive",
            "credential_id": credential_id,
        },
    )
    assert blocked_tool_call.status_code == 200
    assert blocked_tool_call.json()["decision"]["decision"] == "block"

    allowed_tool_call = client.post(
        "/api/v1/gateway/authorize",
        json={
            "agent_id": agent_id,
            "action": "send_email",
            "target": "customer.example",
            "tool": "gmail",
            "credential_id": credential_id,
        },
    )
    assert allowed_tool_call.status_code == 200
    assert allowed_tool_call.json()["decision"]["decision"] == "allow"

    credential_broker.revoke(credential_id)
    agent_registry._agents.pop(agent_id, None)
