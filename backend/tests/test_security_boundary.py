from fastapi.testclient import TestClient

from app.main import app
from app.services import agent_registry, credential_broker

client = TestClient(app)


def test_credential_cannot_be_issued_to_unknown_agent():
    response = client.post("/api/v1/security/credentials", json={"agent_id": "missing", "tool": "crm", "scopes": ["read"]})
    assert response.status_code == 404


def test_credential_scopes_cannot_exceed_agent_permissions():
    agent = agent_registry.register("credential-test", "security", permissions={"read"})
    response = client.post("/api/v1/security/credentials", json={"agent_id": agent.agent_id, "tool": "crm", "scopes": ["delete"]})
    assert response.status_code == 403
    agent_registry._agents.pop(agent.agent_id, None)


def test_suspended_agent_cannot_receive_credentials():
    agent = agent_registry.register("suspended-test", "security", permissions={"read"})
    agent_registry.suspend(agent.agent_id)
    response = client.post("/api/v1/security/credentials", json={"agent_id": agent.agent_id, "tool": "crm", "scopes": ["read"]})
    assert response.status_code == 409
    agent_registry._agents.pop(agent.agent_id, None)


def test_approval_lifecycle():
    created = client.post("/api/v1/approvals", json={"requested_by": "agt_demo"})
    assert created.status_code == 201
    approval_id = created.json()["approval_id"]
    decided = client.post(f"/api/v1/approvals/{approval_id}/decision", json={"approved": True, "decided_by": "operator"})
    assert decided.status_code == 200
    assert decided.json()["status"] == "approved"


def test_agents_list_endpoint():
    agent = agent_registry.register("list-test", "security", permissions={"read"})
    response = client.get("/api/v1/agents")
    assert response.status_code == 200
    assert any(item["agent_id"] == agent.agent_id for item in response.json()["agents"])
    agent_registry._agents.pop(agent.agent_id, None)
