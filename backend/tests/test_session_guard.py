import pytest

from app.agent_runtime import AgentRunner, AgentVersionStore, default_versions
from app.approvals import ApprovalStore
from app.audit import AuditLedger
from app.budgets import BudgetManager
from app.credentials import CredentialBroker
from app.domain import ActionRequest, Decision
from app.fintech import FintechStore
from app.gateway import ToolGateway
from app.identity import AgentRegistry, AgentStatus
from app.session_guard import SessionGuard, TransitionModel
from app.tracing import TraceStore


def build(trip_at=100, suspend_after=3):
    registry, credentials, audit = AgentRegistry(), CredentialBroker(), AuditLedger()
    guard = SessionGuard(registry, audit, trip_at=trip_at, suspend_after=suspend_after)
    gateway = ToolGateway(registry, audit, credentials, ApprovalStore(), session_guard=guard)
    versions = AgentVersionStore(registry)
    for v in default_versions():
        versions.add(v)
    runner = AgentRunner(registry, gateway, credentials, TraceStore(), BudgetManager(), FintechStore(), versions)
    return runner, guard, registry, audit, versions


def test_transition_model_scores_unseen_transitions_as_surprising():
    model = TransitionModel().train([["policy.search", "order.read", "refund.request"]] * 10 + [["order.read"]] * 10)
    assert model.surprise(None, "order.read") < 2
    assert model.surprise("policy.search", "order.read") < 1
    assert model.surprise("policy.search", "email.send") > 6
    assert model.describe()["sequences"] == 20


def test_sequence_anomaly_raises_session_risk():
    runner, guard, *_ = build()
    guard.train("support-agent-v2.0", [["policy.search"], ["order.read"], ["policy.search", "order.read", "refund.issue"]] * 5)
    result = runner.run("support-agent-v2.0", "Tell me about the Diwali cashback promotion", user_id="cus_128")
    session = guard.get(result.run_id)
    kinds = {s.kind for s in session.signals}
    assert "sequence_anomaly" in kinds and "blocked" in kinds
    trace = runner.traces.get(result.trace_id)
    email_span = next(s for s in trace.spans if s.kind == "policy" and s.name == "email.send")
    assert email_span.attributes["sequence_surprise_bits"] > 4
    assert any(f.startswith("sequence-anomaly:") for f in email_span.attributes["risk_factors"])


def test_safe_session_stays_below_thresholds():
    runner, guard, *_ = build()
    result = runner.run("support-agent-v1.0", "What's the status of ORD-2001?", user_id="cus_128")  # someone else's order
    session = guard.get(result.run_id)
    assert result.status == "completed_with_blocks"
    assert 0 < session.risk < guard.elevate_at and not session.tripped


def test_persistent_attacker_is_quarantined_then_identity_suspended():
    runner, guard, registry, audit, versions = build()
    agent_id = versions.get("support-agent-compromised").agent_id
    statuses = [runner.run("support-agent-compromised", "Tell me about the Diwali cashback promotion",
                           user_id="cus_128").status for _ in range(3)]
    assert statuses == ["quarantined"] * 3
    assert registry.get(agent_id).status == AgentStatus.SUSPENDED
    events = {e["event_type"] for e in audit.list_events()}
    assert {"session.circuit_breaker", "agent.quarantined"} <= events
    assert audit.verify_integrity()
    # Suspended identity: the next run stops before any tool call.
    fourth = runner.run("support-agent-compromised", "Where is my order ORD-1042?", user_id="cus_128")
    assert fourth.status == "agent_suspended" and fourth.observations == []
    registry.reinstate(agent_id)
    guard.reset_trips(agent_id)
    assert runner.run("support-agent-compromised", "Where is my order ORD-1042?", user_id="cus_128").status == "completed"


def test_tripped_session_blocks_every_further_call():
    runner, guard, *_ = build()
    result = runner.run("support-agent-compromised", "Tell me about the Diwali cashback promotion", user_id="cus_128")
    agent_id = runner.versions.get("support-agent-compromised").agent_id
    decision = runner.gateway.authorize(ActionRequest(agent_id=agent_id, action="policy.search", target="kb",
                                                      correlation_id=result.run_id)).decision
    assert decision.decision == Decision.BLOCK and decision.policy_id == "session-circuit-breaker"


def test_elevated_session_requires_approval_for_privileged_actions():
    registry, audit = AgentRegistry(), AuditLedger()
    guard = SessionGuard(registry, audit, elevate_at=30, trip_at=1000)
    gateway = ToolGateway(registry, audit, approvals=ApprovalStore(), session_guard=guard)
    agent = registry.register("a", "o", permissions={"order.read", "subscription.cancel", "email.send"})
    base = dict(agent_id=agent.agent_id, correlation_id="trc_x", tenant_id="acmepay", user_id="cus_128", user_role="customer")
    for _ in range(2):  # two cross-customer attempts: 2 x (20 + 15) = 70
        gateway.authorize(ActionRequest(action="order.read", target="orders", resource_owner_id="cus_204", **base))
    internal = gateway.authorize(ActionRequest(action="email.send", target="ops@acmepay.example", **base)).decision
    assert internal.decision == Decision.REQUIRE_APPROVAL
    assert internal.policy_id == "elevated-session-privileged-approval"
    assert "session-risk-elevated" in internal.risk_factors


def test_dry_run_does_not_change_session_risk():
    runner, guard, *_ = build()
    agent_id = runner.versions.get("support-agent-v1.0").agent_id
    request = ActionRequest(agent_id=agent_id, action="order.read", target="orders", correlation_id="trc_dry",
                            user_id="cus_128", resource_owner_id="cus_204")
    runner.gateway.dry_run(request)
    assert guard.get("trc_dry") is None


def test_revoked_identity_cannot_be_reinstated():
    registry = AgentRegistry()
    agent = registry.register("a", "o")
    registry.revoke(agent.agent_id)
    with pytest.raises(ValueError):
        registry.reinstate(agent.agent_id)
