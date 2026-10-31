"""End-to-end tests for the SentinelForge API surface (runtime, approvals, traces, evals)."""

from fastapi.testclient import TestClient

from app.main import app
from app.services import policy_engine

client = TestClient(app)


def run(message, user_id="cus_128", version_id="support-agent-v1.0", **extra):
    response = client.post("/api/v1/runs", json={"message": message, "user_id": user_id, "version_id": version_id, **extra})
    assert response.status_code == 201, response.text
    return response.json()


def test_versions_are_seeded_with_one_released():
    versions = {v["version_id"]: v for v in client.get("/api/v1/agent-versions").json()["versions"]}
    assert {"support-agent-v1.0", "support-agent-v2.0", "support-agent-v2.1"} <= set(versions)
    assert versions["support-agent-v1.0"]["status"] == "released"
    assert "system_prompt" not in versions["support-agent-v1.0"]


def test_run_uses_released_version_by_default():
    body = client.post("/api/v1/runs", json={"message": "Where is my order ORD-1042?", "user_id": "cus_128"}).json()
    assert body["status"] == "completed"
    assert "shipped" in body["output"]


def test_large_refund_pauses_then_resumes_after_finance_approval():
    body = run("My order ORD-1077 arrived damaged, please refund ₹18,000", version_id="support-agent-v2.1")
    assert body["status"] == "awaiting_approval"
    approval_id = body["approval_id"]
    approval = client.get(f"/api/v1/approvals/{approval_id}").json()
    assert approval["approver_role"] == "finance_manager"
    assert approval["context"]["arguments"]["amount"] == 18000

    # Wrong role is rejected, then the right role approves.
    wrong = client.post(f"/api/v1/approvals/{approval_id}/decision",
                        json={"approved": True, "decided_by": "sam", "decided_by_role": "support_manager"})
    assert wrong.status_code == 403
    ok = client.post(f"/api/v1/approvals/{approval_id}/decision",
                     json={"approved": True, "decided_by": "priya", "decided_by_role": "finance_manager"})
    assert ok.json()["status"] == "approved"

    resumed = client.post(f"/api/v1/runs/{body['run_id']}/resume").json()
    assert resumed["status"] == "completed"
    assert "has been issued" in resumed["output"]
    assert client.get(f"/api/v1/approvals/{approval_id}").json()["status"] == "consumed"
    # A consumed approval cannot be replayed.
    assert client.post(f"/api/v1/runs/{body['run_id']}/resume").status_code == 409


def test_denied_approval_is_reported_to_customer():
    body = run("Please cancel my AcmePay Plus subscription.", user_id="cus_204")
    approval_id = body["approval_id"]
    client.post(f"/api/v1/approvals/{approval_id}/decision",
                json={"approved": False, "decided_by": "sam", "note": "Retention offer first"})
    resumed = client.post(f"/api/v1/runs/{body['run_id']}/resume").json()
    assert resumed["status"] == "completed"
    assert "Retention offer first" in resumed["output"]


def test_trace_explorer_links_spans_audit_and_policies():
    body = run("Tell me about the Diwali cashback promotion", version_id="support-agent-v2.0")
    trace = client.get(f"/api/v1/traces/{body['trace_id']}").json()
    kinds = {span["kind"] for span in trace["spans"]}
    assert {"llm", "policy", "tool", "retrieval"} <= kinds
    assert "injected-instruction-privileged-action" in trace["policies"]
    assert trace["blocked_actions"] >= 1
    assert any(e["policy_id"] == "injected-instruction-privileged-action" for e in trace["audit_events"])
    listed = client.get("/api/v1/traces", params={"policy": "injected-instruction-privileged-action"}).json()["traces"]
    assert any(t["trace_id"] == body["trace_id"] for t in listed)


def test_observability_stats_and_prometheus_metrics():
    run("Where is my order ORD-1042?")
    stats = client.get("/api/v1/observability/stats").json()
    assert stats["runs"] >= 1 and "p95_latency_ms" in stats
    metrics = client.get("/api/v1/observability/metrics")
    assert metrics.status_code == 200
    assert "sentinelforge_gateway_decisions_total" in metrics.text
    assert 'sentinelforge_audit_chain_valid 1' in metrics.text


def test_budget_endpoint_tracks_usage():
    run("Where is my order ORD-1042?")
    usage = client.get("/api/v1/budgets/acmepay").json()
    assert usage["tokens_used"] > 0


def test_evaluation_blocks_regressed_version_and_approves_fix():
    bad = client.post("/api/v1/evaluations", json={"version_id": "support-agent-v2.0"}).json()
    good = client.post("/api/v1/evaluations", json={"version_id": "support-agent-v2.1"}).json()
    assert bad["release_decision"] == "blocked"
    assert good["release_decision"] == "approved"
    failed = {g["metric"] for g in bad["gates"] if not g["passed"]}
    assert "injection_resistance" in failed
    assert bad["summary"]["metrics"]["containment"] == 1.0  # the gateway contained every attempt

    comparison = client.post("/api/v1/evaluations/compare",
                             json={"baseline_id": bad["evaluation_id"], "candidate_id": good["evaluation_id"]}).json()
    assert comparison["fixes"] and not comparison["regressions"]
    assert comparison["metric_deltas"]["injection_resistance"]["delta"] > 0.5

    detail = client.get(f"/api/v1/evaluations/{bad['evaluation_id']}", params={"failed_only": True}).json()
    assert detail["cases"] and all(not c["passed"] for c in detail["cases"])
    evidence = client.get(f"/api/v1/traces/{detail['cases'][0]['trace_id']}")
    assert evidence.status_code == 200


def test_promotion_requires_passing_release_gate():
    client.post("/api/v1/evaluations", json={"version_id": "support-agent-v2.0"})
    assert client.post("/api/v1/agent-versions/support-agent-v2.0/promote").status_code == 409
    client.post("/api/v1/evaluations", json={"version_id": "support-agent-v2.1"})
    promoted = client.post("/api/v1/agent-versions/support-agent-v2.1/promote").json()
    assert promoted["status"] == "released"
    versions = {v["version_id"]: v for v in client.get("/api/v1/agent-versions").json()["versions"]}
    assert versions["support-agent-v1.0"]["status"] == "superseded"


def test_create_candidate_version_validates_flags():
    bad = client.post("/api/v1/agent-versions", json={"version_id": "support-agent-x", "behavior": {"nope": True}})
    assert bad.status_code == 422
    created = client.post("/api/v1/agent-versions", json={"version_id": "support-agent-v3.0-test",
                                                          "behavior": {"refund_mode": "issue"}})
    assert created.status_code == 201 and created.json()["status"] == "candidate"
    assert client.post("/api/v1/agent-versions/support-agent-v3.0-test/promote").status_code == 409


def test_red_team_report_shape():
    report = client.post("/api/v1/redteam/run", json={"version_id": "support-agent-v2.0",
                                                      "attack_types": ["indirect_exfil_email"]}).json()
    assert report["total"] == 5
    first = report["results"][0]
    for key in ["attack_type", "input_source", "agent_response", "tool_calls_attempted", "sensitive_data_exposed",
                "passed", "remediation"]:
        assert key in first
    assert all(r["gateway_contained"] for r in report["results"])
    assert not any(r["agent_resisted"] for r in report["results"])


def test_orchestrator_least_privilege_blocks_billing_overreach():
    agents = client.get("/api/v1/orchestrations/agents").json()["agents"]
    assert agents["billing"]["permissions"] == ["refund.request"]
    body = client.post("/api/v1/orchestrations/run", json={
        "message": "My order ORD-1077 arrived damaged, please refund ₹18,000", "user_id": "cus_128",
        "simulate_overreach": True}).json()
    assert body["route"] == ["policy", "order", "billing"]
    billing = [s for s in body["steps"] if s["agent"] == "billing"]
    assert billing[0]["action"] == "refund.issue" and billing[0]["decision"] == "block"
    assert "permission" in billing[0]["reason"]
    assert billing[1]["action"] == "refund.request" and billing[1]["executed"]
    assert "blocked by policy" in body["output"]


def test_policy_simulation_and_hot_reload():
    simulated = client.post("/api/v1/policies/simulate", json={
        "agent_id": client.get("/api/v1/agent-versions/support-agent-v1.0").json()["agent_id"],
        "action": "refund.issue", "target": "payments", "execution_payload": {"order_id": "ORD-1077", "amount": 18000}}).json()
    assert simulated["decision"]["decision"] == "require_approval"

    bad = client.post("/api/v1/policies/validate", json={"version": "x", "policies": [
        {"id": "a", "when": {"amount_gt": 1}, "decision": "deny"}]})
    assert bad.status_code == 422

    original = policy_engine.describe()
    try:
        replaced = client.post("/api/v1/policies", json={"version": "test-pack", "policies": [
            {"id": "deny-all-email", "when": {"action": "email.send"}, "decision": "deny"}]})
        assert replaced.status_code == 200 and replaced.json()["version"] == "test-pack"
        assert client.get("/api/v1/policies/history").json()["history"][0]["version"] == "test-pack"
    finally:
        client.post("/api/v1/policies", json=original)
    assert policy_engine.version == original["version"]


def test_reviewer_role_can_decide_and_resume_but_not_run(monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "operators", "rev-key:reviewer,admin-key:admin")
    monkeypatch.setattr(settings, "api_key", None)
    headers = {"x-api-key": "rev-key"}
    assert client.post("/api/v1/runs", json={"message": "hi"}, headers=headers).status_code == 403
    assert client.post("/api/v1/runs/x/resume", headers=headers).status_code == 404
    assert client.post("/api/v1/approvals/none/decision", headers=headers,
                       json={"approved": True, "decided_by": "r"}).status_code == 404
    assert client.get("/api/v1/traces", headers=headers).status_code == 200
