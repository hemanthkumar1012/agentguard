import copy

import pytest
from fastapi.testclient import TestClient

from app.approvals import ApprovalStore
from app.audit import AuditLedger
from app.domain import ActionRequest, Decision
from app.gateway import ToolGateway
from app.identity import AgentRegistry
from app.main import app
from app.policy_engine import PolicyEngine, default_engine, default_rules
from app.policy_rollout import PolicyRollout, diff_packs, replay

client = TestClient(app)


def candidate_with(threshold: int, version: str = "candidate") -> PolicyEngine:
    rules = copy.deepcopy(default_rules())
    for r in rules:
        if r["id"] == "refund-above-threshold":
            r["when"]["amount_greater_than"] = threshold
    return PolicyEngine.from_dicts(rules, version=version)


def setup():
    registry = AgentRegistry()
    agent = registry.register("support", "ops", permissions={"refund.issue", "order.read"})
    rollout = PolicyRollout()
    gateway = ToolGateway(registry, AuditLedger(), approvals=ApprovalStore(), rollout=rollout)
    return agent, gateway, rollout


def refund(agent, amount, tenant="acmepay", corr=None):
    return ActionRequest(agent_id=agent.agent_id, action="refund.issue", target="payments", tenant_id=tenant,
                         correlation_id=corr, execution_payload={"order_id": "ORD-1077", "amount": amount,
                                                                 "note": "call me on 9876543210"})


def test_decision_log_stores_policy_inputs_without_secrets():
    agent, gateway, rollout = setup()
    gateway.authorize(refund(agent, 18000).model_copy(update={"content": "secret: hunter2", "credential_token": "tok"}))
    record = rollout.records()[0]
    assert record.live_decision == "require_approval"
    assert "content" not in record.request and "credential_token" not in record.request
    assert "9876543210" not in str(record.request["execution_payload"])
    assert record.request["execution_payload"]["amount"] == 18000


def test_replay_classifies_relaxation_and_tightening():
    agent, gateway, rollout = setup()
    for amount in (900, 7000, 18000):
        gateway.authorize(refund(agent, amount))
    looser = replay(rollout.records(), default_engine(), candidate_with(20000))
    assert looser["relaxed"] == 2 and looser["tightened"] == 0
    assert looser["transitions"]["require_approval"]["allow"] == 2
    stricter = replay(rollout.records(), default_engine(), candidate_with(500))
    assert stricter["tightened"] == 1 and stricter["relaxed"] == 0


def test_shadow_records_disagreements_but_never_enforces():
    agent, gateway, rollout = setup()
    rollout.start_shadow(candidate_with(20000, "shadow-pack"))
    result = gateway.authorize(refund(agent, 18000)).decision
    assert result.decision == Decision.REQUIRE_APPROVAL      # live pack still enforced
    assert result.shadow_decision == "allow"
    report = rollout.shadow_report()
    assert report["decisions"] == 1 and report["looser"] == 1
    assert report["disagreements"][0]["shadow"] == "allow"


def test_canary_enforces_candidate_only_for_selected_tenants():
    agent, gateway, rollout = setup()
    rollout.start_canary(candidate_with(500, "canary-pack"), tenants=["zenbank"], percent=0)
    canary = gateway.authorize(refund(agent, 900, tenant="zenbank")).decision
    live = gateway.authorize(refund(agent, 900, tenant="acmepay")).decision
    assert canary.decision == Decision.REQUIRE_APPROVAL and canary.policy_pack == "canary-pack"
    assert live.decision == Decision.ALLOW and live.policy_pack == default_engine().version


def test_canary_percentage_is_sticky_per_session():
    agent, gateway, rollout = setup()
    rollout.start_canary(candidate_with(500), tenants=[], percent=50)
    packs = {gateway.authorize(refund(agent, 900, corr="trc_same")).decision.policy_pack for _ in range(5)}
    assert len(packs) == 1


def test_canary_auto_rolls_back_on_strictness_shift():
    agent, gateway, rollout = setup()
    rollout.start_canary(candidate_with(100), tenants=["zenbank"], percent=0)
    rollout.canary.min_decisions = 5
    for i in range(6):
        gateway.authorize(refund(agent, 900, tenant="acmepay", corr=f"live{i}"))
    for i in range(6):
        gateway.authorize(refund(agent, 900, tenant="zenbank", corr=f"can{i}"))
    assert rollout.canary is None
    assert rollout.history[-1]["event"] == "canary_rolled_back"
    assert "automatic" in rollout.history[-1]["reason"]


def test_canary_validation():
    rollout = PolicyRollout()
    with pytest.raises(ValueError):
        rollout.start_canary(default_engine(), tenants=[], percent=0)
    with pytest.raises(ValueError):
        rollout.start_canary(default_engine(), tenants=[], percent=80)


def test_pack_diff():
    diff = diff_packs(default_engine().rules, candidate_with(20000).rules)
    assert diff["changed"][0]["id"] == "refund-above-threshold"
    assert diff["changed"][0]["after"]["when"]["amount_greater_than"] == 20000


# --------------------------------------------------------------------------- API
def pack(threshold, version):
    return {"version": version, "policies": [r.model_dump(mode="json") for r in candidate_with(threshold).rules]}


def test_impact_api_flags_unsafe_relaxation():
    only_v1 = client.post("/api/v1/policies/impact", json={**pack(20000, "raise-threshold"),
                                                           "agent_versions": ["support-agent-v1.0"],
                                                           "include_live_history": False}).json()
    assert only_v1["evaluation_corpus"]["relaxed"] == 0   # v1.0 drafts refunds: unaffected
    report = client.post("/api/v1/policies/impact", json={**pack(20000, "raise-threshold"),
                                                          "include_live_history": False}).json()
    assert set(report["agent_versions"]) >= {"support-agent-v1.0", "support-agent-v2.1"}
    assert "support-agent-compromised" not in report["agent_versions"]
    assert report["verdict"] == "unsafe"
    assert "support-agent-v2.1" in report["regressed_versions"]
    assert "support-agent-v1.0" not in report["regressed_versions"]
    assert report["evaluation_corpus"]["relaxed"] >= 4
    assert any(g["regressed"] for g in report["release_gates"]["support-agent-v2.1"]["gates"])
    # v2.0 was already blocked overall, so its *release* did not regress (individual gates may)
    assert not report["release_gates"]["support-agent-v2.0"]["release_regressed"]


def test_impact_api_reports_no_change_for_identical_pack():
    live = client.get("/api/v1/policies").json()
    report = client.post("/api/v1/policies/impact", json={**live, "version": "same", "run_gates": False}).json()
    assert report["verdict"] == "no_change"


def test_shadow_and_canary_api_lifecycle():
    assert client.post("/api/v1/policies/shadow", json=pack(20000, "shadow-api")).json()["active"] is True
    client.post("/api/v1/runs", json={"version_id": "support-agent-v2.1", "user_id": "cus_128",
                                      "message": "My order ORD-1077 arrived damaged, please refund ₹18,000"})
    report = client.post("/api/v1/policies/shadow/stop").json()
    assert report["looser"] >= 1
    assert client.get("/api/v1/policies/shadow").json()["active"] is False

    started = client.post("/api/v1/policies/canary", json={**pack(4000, "canary-api"), "tenants": ["zenbank"]})
    assert started.status_code == 200 and started.json()["tenants"] == ["zenbank"]
    assert client.get("/api/v1/policies/canary").json()["canary"]["version"] == "canary-api"
    assert client.post("/api/v1/policies/canary/rollback").status_code == 200
    assert client.post("/api/v1/policies/canary/promote", json={}).status_code == 404


def test_relaxing_canary_requires_acknowledgement():
    # Make sure the live log has an approval-requiring refund to protect.
    client.post("/api/v1/runs", json={"version_id": "support-agent-v2.1", "user_id": "cus_128",
                                      "message": "My order ORD-1077 arrived damaged, please refund ₹18,000"})
    blocked = client.post("/api/v1/policies/canary", json={**pack(50000, "loose"), "tenants": ["zenbank"]})
    assert blocked.status_code == 409
    assert "less strict" in blocked.json()["detail"]["message"]
    ok = client.post("/api/v1/policies/canary", json={**pack(50000, "loose"), "tenants": ["zenbank"],
                                                      "acknowledge_relaxations": True})
    assert ok.status_code == 200
    client.post("/api/v1/policies/canary/rollback")


def test_decision_log_endpoint():
    body = client.get("/api/v1/policies/decision-log", params={"limit": 5}).json()
    assert body["total"] >= 1 and len(body["records"]) <= 5
