from fastapi.testclient import TestClient

from app.config import settings
from app.main import app


client = TestClient(app)


def test_viewer_can_read_but_cannot_mutate(monkeypatch):
    monkeypatch.setattr(settings, "api_key", None)
    monkeypatch.setattr(settings, "operators", "viewer-key:viewer")

    read = client.get("/api/v1/control-plane/snapshot", headers={"x-api-key": "viewer-key"})
    assert read.status_code == 200

    write = client.post(
        "/api/v1/agents",
        headers={"x-api-key": "viewer-key"},
        json={"name": "blocked", "owner": "operator", "permissions": []},
    )
    assert write.status_code == 403


def test_reviewer_can_decide_approvals_but_not_register_agents(monkeypatch):
    monkeypatch.setattr(settings, "api_key", None)
    monkeypatch.setattr(settings, "operators", "review-key:reviewer")

    created = client.post(
        "/api/v1/approvals",
        headers={"x-api-key": "review-key"},
        json={"requested_by": "agt_demo"},
    )
    assert created.status_code == 403

    decision = client.post(
        "/api/v1/approvals/missing/decision",
        headers={"x-api-key": "review-key"},
        json={"approved": True, "decided_by": "operator"},
    )
    assert decision.status_code == 404

    write = client.post(
        "/api/v1/agents",
        headers={"x-api-key": "review-key"},
        json={"name": "blocked", "owner": "operator", "permissions": []},
    )
    assert write.status_code == 403


def test_legacy_api_key_remains_admin(monkeypatch):
    monkeypatch.setattr(settings, "operators", None)
    monkeypatch.setattr(settings, "api_key", "legacy-admin")

    response = client.post(
        "/api/v1/agents",
        headers={"x-api-key": "legacy-admin"},
        json={"name": "legacy-admin-agent", "owner": "operator", "permissions": []},
    )
    assert response.status_code == 201
