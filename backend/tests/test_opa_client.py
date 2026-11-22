"""The optional OPA path must fail closed: no answer from OPA means block."""
import httpx
import pytest

from app import gateway as gateway_module
from app.audit import AuditLedger
from app.domain import ActionRequest, Decision
from app.gateway import ToolGateway
from app.identity import AgentRegistry


class FakeResponse:
    def __init__(self, payload, status=200):
        self._payload, self.status_code = payload, status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("bad status", request=None, response=None)

    def json(self):
        return self._payload


@pytest.fixture
def opa_gateway(monkeypatch):
    monkeypatch.setattr(gateway_module.settings, "opa_url", "http://opa.test:8181")
    registry = AgentRegistry()
    agent = registry.register("mailer", "team", permissions={"send_email"})
    return ToolGateway(registry, AuditLedger()), agent.agent_id


def authorize(gateway, agent_id):
    return gateway.authorize(ActionRequest(agent_id=agent_id, action="send_email", target="https://mail.example.com"))


def test_opa_decision_is_used(opa_gateway, monkeypatch):
    sent = {}

    def fake_post(url, json, timeout):
        sent.update(url=url, input=json["input"])
        return FakeResponse({"result": {"decision": "allow", "reason": "ok from opa"}})

    monkeypatch.setattr("app.opa_client.httpx.post", fake_post)
    result = authorize(*opa_gateway)
    assert result.decision.decision == Decision.ALLOW
    assert result.decision.reason == "ok from opa"
    assert sent["url"] == "http://opa.test:8181/v1/data/agentguard"
    assert sent["input"]["agent"]["permissions"] == {"send_email": True}


@pytest.mark.parametrize("behaviour", ["unreachable", "server_error", "empty_result", "unknown_decision"])
def test_opa_problems_block_the_request(opa_gateway, monkeypatch, behaviour):
    def fake_post(url, json, timeout):
        if behaviour == "unreachable":
            raise httpx.ConnectError("connection refused")
        if behaviour == "server_error":
            return FakeResponse({}, status=500)
        if behaviour == "empty_result":
            return FakeResponse({"result": {}})
        return FakeResponse({"result": {"decision": "maybe"}})

    monkeypatch.setattr("app.opa_client.httpx.post", fake_post)
    result = authorize(*opa_gateway)
    assert result.decision.decision == Decision.BLOCK
    assert "fail closed" in result.decision.reason
    assert "policy-engine-unavailable" in result.decision.risk_factors
