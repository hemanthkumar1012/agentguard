"""Replays traces through a fresh gateway under different configurations."""
from __future__ import annotations

from dataclasses import dataclass

from app.audit import AuditLedger
from app.data_inspector import inspect_outbound
from app.domain import ActionRequest, Decision
from app.flow.engine import FlowEngine
from app.flow.fingerprints import FingerprintIndex
from app.flow.labels import DestinationRegistry, ManifestRegistry
from app.flow.output import check_output
from app.flow.engine import default_manifests
from app.gateway import ToolGateway
from app.identity import AgentRegistry
from benchmarks import legacy_inspector
from benchmarks.traces import Trace

CONFIGS = {
    "legacy": "before this change: old regex inspector, no data-flow rules",
    "inspector": "new inspector only (validators, decoding, severities), no data-flow rules",
    "labels": "new inspector + session labels (rules F1, F2, F4); fingerprints and piece tracking off",
    "full": "new inspector + session labels + fingerprints + piece tracking (all rules)",
}


class _NoPieces:
    def add(self, **kwargs):
        return False

    def observe(self, *args):
        return []


@dataclass(frozen=True)
class StepResult:
    tool: str
    action: str
    session: str
    decision: Decision
    rule: str | None
    reason: str
    exit: bool


def _gateway(trace: Trace, config: str, sessions=None) -> tuple[ToolGateway, str, FlowEngine | None]:
    registry = AgentRegistry()
    agent = registry.register("bench", "bench", permissions={s.action for s in trace.steps})
    flow = None
    if config in {"labels", "full"}:
        manifests = ManifestRegistry(default_manifests() + list(trace.manifests))
        destinations = DestinationRegistry()
        for pattern, audience in trace.destinations:
            destinations.register(pattern, audience)
        index = FingerprintIndex(min_shared=10**9) if config == "labels" else FingerprintIndex()
        pieces = _NoPieces() if config == "labels" else None
        flow = FlowEngine(manifests=manifests, destinations=destinations, index=index, sessions=sessions, pieces=pieces)
    inspector = (lambda c, p: legacy_inspector.inspect_outbound(c, p)) if config == "legacy" else inspect_outbound
    return ToolGateway(registry, AuditLedger(), flow=flow, inspector=inspector), agent.agent_id, flow


def replay(trace: Trace, config: str, sessions=None) -> list[StepResult]:
    """`sessions` swaps in another label store (e.g. Redis) for the full and labels configurations."""
    gateway, agent_id, flow = _gateway(trace, config, sessions)
    sessions: dict[str, str | None] = {}
    results: list[StepResult] = []
    for step in trace.steps:
        if step.session not in sessions:
            sessions[step.session] = flow.sessions.create(agent_id, step.session).session_id if flow else None
        if step.action == "render_output":
            # The client renders the model's reply. Without the output check nothing looks at it.
            checked = check_output(flow, agent_id, sessions[step.session], step.payload["text"]) if flow else None
            removed = bool(checked and checked.removed)
            results.append(StepResult(step.tool, step.action, step.session,
                                      Decision.BLOCK if removed else Decision.ALLOW, "O1" if removed else None,
                                      checked.removed[0].reason if removed else "rendered unchanged", step.exit))
            continue
        request = ActionRequest(
            agent_id=agent_id, tool=step.tool, action=step.action, target=step.target or step.tool,
            data_classification="public", risk_score=0,       # the agent claims the most convenient labels
            execution_payload=step.payload, session_id=sessions[step.session],
        )
        result = gateway.authorize(request)
        if result.decision.decision == Decision.ALLOW and step.output is not None:
            gateway.record_output(request, result.event_id, step.output)
        results.append(StepResult(step.tool, step.action, step.session, result.decision.decision,
                                  result.decision.flow_rule, result.decision.reason, step.exit))
    return results


def outcome(trace: Trace, results: list[StepResult]) -> str:
    if trace.kind == "attack":
        exits = [r for r in results if r.exit]
        return "stopped" if any(r.decision != Decision.ALLOW for r in exits) else "missed"
    worst = max(results, key=lambda r: {Decision.ALLOW: 0, Decision.REQUIRE_APPROVAL: 1, Decision.BLOCK: 2}[r.decision])
    return {Decision.ALLOW: "allow", Decision.REQUIRE_APPROVAL: "approval", Decision.BLOCK: "blocked"}[worst.decision]


def stopping_step(results: list[StepResult]) -> StepResult | None:
    return next((r for r in results if r.decision != Decision.ALLOW), None)
