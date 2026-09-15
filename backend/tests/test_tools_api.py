from fastapi.testclient import TestClient

from app.main import app
from app.services import agent_registry, credential_broker


client = TestClient(app)


def test_tool_execution_requires_gateway_authorization():
    agent = agent_registry.register("demo-executor", "security", environment="test", permissions={"echo"})
    credential = credential_broker.issue(agent.agent_id, "demo", {"echo"})

    executed = client.post("/api/v1/tools/execute", json={
        "agent_id": agent.agent_id, "tool": "demo", "action": "echo", "target": "internal-demo",
        "credential_id": credential.credential_id, "credential_token": credential.token, "payload": {"message": "hello"},
    })
    assert executed.status_code == 200
    assert executed.json()["executed"] is True
    assert executed.json()["tool_result"]["payload"]["message"] == "hello"

    denied = client.post("/api/v1/tools/execute", json={
        "agent_id": agent.agent_id, "tool": "demo", "action": "echo", "target": "internal-demo",
        "credential_id": "missing-credential", "credential_token": "wrong", "payload": {"message": "should not execute"},
    })
    assert denied.status_code == 200
    assert denied.json()["executed"] is False
    assert denied.json()["decision"]["decision"] == "block"

    credential_broker.revoke(credential.credential_id)
    agent_registry._agents.pop(agent.agent_id, None)
