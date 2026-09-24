from fastapi.testclient import TestClient

from app.config import settings
from app.main import app
from app.services import agent_registry

client = TestClient(app)


def test_browser_token_is_scoped_to_agent(monkeypatch):
    monkeypatch.setattr(settings, "api_key", "browser-test-secret")
    agent = agent_registry.register(
        "browser-agent",
        "security",
        permissions={"submit_prompt"},
    )

    response = client.post(
        "/api/v1/security/browser-token",
        headers={"x-api-key": "browser-test-secret"},
        json={"agent_id": agent.agent_id, "ttl_seconds": 3600},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["agent_id"] == agent.agent_id
    assert body["scope"] == ["browser:inspect", "browser:approval"]
    assert body["token"].count(".") == 2

    agent_registry._agents.pop(agent.agent_id, None)


def test_browser_inspection_uses_runtime_gateway(monkeypatch):
    monkeypatch.setattr(settings, "api_key", "browser-test-secret")
    agent = agent_registry.register(
        "browser-runtime-agent",
        "security",
        permissions={"submit_prompt"},
    )

    issued = client.post(
        "/api/v1/security/browser-token",
        headers={"x-api-key": "browser-test-secret"},
        json={"agent_id": agent.agent_id, "ttl_seconds": 3600},
    )
    token = issued.json()["token"]

    response = client.post(
        "/browser/v1/inspect",
        headers={"authorization": f"Bearer {token}"},
        json={
            "site": "example-ai.app",
            "page_url": "https://example-ai.app",
            "page_title": "AgentGuard test",
            "action": "submit_prompt",
            "target": "example-ai.app",
            "content": "Summarize this public text",
        },
    )

    assert response.status_code == 200
    assert response.json()["decision"] == "allow"
    assert response.json()["agent_id"] == agent.agent_id

    agent_registry._agents.pop(agent.agent_id, None)


def test_browser_sensitive_content_requests_approval(monkeypatch):
    monkeypatch.setattr(settings, "api_key", "browser-test-secret")
    agent = agent_registry.register(
        "browser-sensitive-agent",
        "security",
        permissions={"submit_prompt"},
    )

    issued = client.post(
        "/api/v1/security/browser-token",
        headers={"x-api-key": "browser-test-secret"},
        json={"agent_id": agent.agent_id, "ttl_seconds": 3600},
    )
    token = issued.json()["token"]

    response = client.post(
        "/browser/v1/inspect",
        headers={"authorization": f"Bearer {token}"},
        json={
            "site": "example-ai.app",
            "page_url": "https://example-ai.app",
            "page_title": "Sensitive prompt",
            "action": "submit_prompt",
            "target": "example-ai.app",
            "content": "Use api_key=sk_live_1234567890abcdef for the deployment",
        },
    )

    assert response.status_code == 200
    assert response.json()["decision"] == "require_approval"
    assert response.json()["approval_id"]

    agent_registry._agents.pop(agent.agent_id, None)


def test_browser_token_rejects_tampering(monkeypatch):
    monkeypatch.setattr(settings, "api_key", "browser-test-secret")
    agent = agent_registry.register(
        "browser-tamper-agent",
        "security",
        permissions={"submit_prompt"},
    )
    issued = client.post(
        "/api/v1/security/browser-token",
        headers={"x-api-key": "browser-test-secret"},
        json={"agent_id": agent.agent_id, "ttl_seconds": 3600},
    )
    token = issued.json()["token"]
    tampered = token[:-1] + ("a" if token[-1] != "a" else "b")

    response = client.post(
        "/browser/v1/inspect",
        headers={"authorization": f"Bearer {tampered}"},
        json={
            "site": "example-ai.app",
            "page_url": "https://example-ai.app",
            "content": "hello",
        },
    )

    assert response.status_code == 401
    agent_registry._agents.pop(agent.agent_id, None)
