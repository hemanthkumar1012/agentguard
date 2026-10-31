"""Session-level risk: sequence anomaly detection, cumulative risk and a circuit breaker.

Single decisions can each look acceptable while the *session* is clearly going wrong:
an agent that reads a policy document and then immediately tries to email someone, gets
blocked, tries an export, gets blocked again. The session guard watches the sequence.

* ``TransitionModel`` is a first-order Markov model of tool-call sequences per agent
  version, trained only on benign runs that *passed* their evaluation case. An unseen or
  rare transition (``policy.search -> email.send``) carries high surprise (bits).
* ``SessionGuard`` accumulates risk per session (correlation/trace id) from decisions,
  injection signals, cross-customer attempts, sequence surprise and velocity.
  - ``elevate_at``: the ``session_risk_at_least`` policy condition starts matching, so
    privileged actions in the session require human approval (dynamic tightening).
  - ``trip_at``: the circuit breaker opens; every further call in the session is blocked
    and the run is quarantined.
  - ``suspend_after`` trips by the same agent identity within ``window_seconds`` suspend
    the identity (kill switch) until an operator reinstates it.
"""

from __future__ import annotations

import math
import time
from collections import Counter, OrderedDict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from threading import Lock
from typing import Any

START = "<start>"


class TransitionModel:
    """First-order Markov chain over tool actions with additive smoothing."""

    def __init__(self, alpha: float = 0.1) -> None:
        self.alpha = alpha
        self.counts: dict[str, Counter] = {}
        self.vocabulary: set[str] = set()
        self.sequences = 0

    def train(self, sequences: list[list[str]]) -> "TransitionModel":
        for sequence in sequences:
            self.sequences += 1
            prev = START
            for action in sequence:
                self.counts.setdefault(prev, Counter())[action] += 1
                self.vocabulary.add(action)
                prev = action
        return self

    def probability(self, prev: str, nxt: str) -> float:
        row = self.counts.get(prev or START, Counter())
        vocab = len(self.vocabulary | {nxt}) + 1  # +1 reserves mass for never-seen actions
        return (row.get(nxt, 0) + self.alpha) / (sum(row.values()) + self.alpha * vocab)

    def surprise(self, prev: str | None, nxt: str) -> float:
        """Information content of the transition in bits (higher = more anomalous)."""
        return round(-math.log2(self.probability(prev or START, nxt)), 3)

    def describe(self, limit: int = 25) -> dict:
        edges = []
        for prev, row in self.counts.items():
            total = sum(row.values())
            for nxt, count in row.items():
                edges.append({"from": prev, "to": nxt, "count": count, "probability": round(count / total, 4)})
        edges.sort(key=lambda e: (-e["count"], e["from"], e["to"]))
        return {"sequences": self.sequences, "actions": sorted(self.vocabulary), "transitions": edges[:limit],
                "edge_count": len(edges)}


@dataclass
class SessionSignal:
    kind: str
    weight: float
    detail: str
    action: str
    at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class SessionState:
    session_id: str
    agent_id: str
    agent_key: str | None
    tenant_id: str | None
    risk: float = 0.0
    last_action: str | None = None
    actions: int = 0
    elevated: bool = False
    tripped: bool = False
    tripped_at: str | None = None
    signals: list[SessionSignal] = field(default_factory=list)
    timestamps: deque = field(default_factory=lambda: deque(maxlen=50))
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self, full: bool = False) -> dict:
        data = {
            "session_id": self.session_id, "agent_id": self.agent_id, "agent_version": self.agent_key,
            "tenant_id": self.tenant_id, "risk": round(self.risk, 2), "actions": self.actions,
            "elevated": self.elevated, "tripped": self.tripped, "tripped_at": self.tripped_at,
            "started_at": self.started_at, "last_action": self.last_action,
        }
        if full:
            data["signals"] = [s.__dict__ for s in self.signals]
        return data


@dataclass(frozen=True)
class SessionAssessment:
    risk: float
    surprise: float | None
    anomaly_weight: float
    elevated: bool
    tripped: bool
    previous_action: str | None


# Signal weights. Tuned so a correct agent that hits one or two blocks (e.g. it tried to read
# an order that turned out to belong to someone else) stays well below the trip threshold,
# while an agent repeatedly attempting injected actions trips within a few calls.
WEIGHTS = {
    "blocked": 20.0,
    "rate_limited": 10.0,
    "cross_boundary": 15.0,
    "injection": 10.0,
    "human_hold": 5.0,
    "velocity": 15.0,
}
ANOMALY_FREE_BITS = 4.0     # transitions below this surprise are normal variation
ANOMALY_BITS_WEIGHT = 4.0   # risk per bit above the free allowance
ANOMALY_MAX = 25.0
VELOCITY_LIMIT = 20         # actions per 60s within one session


class SessionGuard:
    def __init__(self, registry=None, audit=None, elevate_at: float = 60, trip_at: float = 100,
                 suspend_after: int = 3, window_seconds: int = 600, capacity: int = 5000) -> None:
        self.registry = registry
        self.audit = audit
        self.elevate_at = elevate_at
        self.trip_at = trip_at
        self.suspend_after = suspend_after
        self.window_seconds = window_seconds
        self.capacity = capacity
        self.models: dict[str, TransitionModel] = {}
        self._sessions: "OrderedDict[str, SessionState]" = OrderedDict()
        self._trips: dict[str, deque] = {}
        self._quarantine_log: list[dict] = []
        self._lock = Lock()

    # ------------------------------------------------------------------ models
    def train(self, agent_key: str, sequences: list[list[str]]) -> TransitionModel:
        model = TransitionModel().train([s for s in sequences if s])
        self.models[agent_key] = model
        return model

    def share_models_with(self, other: "SessionGuard") -> None:
        other.models = self.models  # read-only sharing (evaluation sandboxes)

    def _key(self, agent_id: str) -> str | None:
        if self.registry is None:
            return None
        agent = self.registry.get(agent_id)
        return agent.name if agent else None

    # ------------------------------------------------------------------ sessions
    def _session(self, session_id: str, agent_id: str, tenant_id: str | None) -> SessionState:
        state = self._sessions.get(session_id)
        if state is None:
            state = SessionState(session_id, agent_id, self._key(agent_id), tenant_id)
            self._sessions[session_id] = state
            while len(self._sessions) > self.capacity:
                self._sessions.popitem(last=False)
        return state

    def get(self, session_id: str) -> SessionState | None:
        return self._sessions.get(session_id)

    def is_tripped(self, session_id: str | None) -> bool:
        state = self._sessions.get(session_id or "")
        return bool(state and state.tripped)

    def assess(self, session_id: str | None, agent_id: str, action: str) -> SessionAssessment:
        """Read-only view used *before* a decision (safe for dry runs)."""
        if not session_id:
            return SessionAssessment(0.0, None, 0.0, False, False, None)
        state = self._sessions.get(session_id)
        prev = state.last_action if state else None
        key = state.agent_key if state else self._key(agent_id)
        model = self.models.get(key or "")
        surprise = model.surprise(prev, action) if model else None
        weight = 0.0
        if surprise is not None and surprise > ANOMALY_FREE_BITS:
            weight = min(ANOMALY_MAX, (surprise - ANOMALY_FREE_BITS) * ANOMALY_BITS_WEIGHT)
        risk = (state.risk if state else 0.0) + weight
        return SessionAssessment(round(risk, 2), surprise, round(weight, 2), risk >= self.elevate_at,
                                 bool(state and state.tripped), prev)

    def record(self, request, decision, assessment: SessionAssessment) -> dict | None:
        """Update the session after an enforced decision. Returns trip details when the breaker opens."""
        if not request.correlation_id:
            return None
        with self._lock:
            state = self._session(request.correlation_id, request.agent_id, request.tenant_id)
            if state.tripped:
                return None
            now = time.monotonic()
            state.timestamps.append(now)
            state.actions += 1
            signals: list[SessionSignal] = []
            value = decision.decision.value
            if assessment.anomaly_weight:
                signals.append(SessionSignal("sequence_anomaly", assessment.anomaly_weight,
                                             f"{assessment.previous_action or START} -> {request.action} "
                                             f"({assessment.surprise} bits)", request.action))
            if value == "block":
                signals.append(SessionSignal("blocked", WEIGHTS["blocked"], decision.reason, request.action))
            if value == "rate_limit":
                signals.append(SessionSignal("rate_limited", WEIGHTS["rate_limited"], decision.reason, request.action))
            if decision.policy_id in {"cross-customer-data-access", "cross-tenant-access"}:
                signals.append(SessionSignal("cross_boundary", WEIGHTS["cross_boundary"], decision.policy_id, request.action))
            if any(f.startswith("prompt-injection:") for f in decision.risk_factors) and (
                decision.policy_id == "injected-instruction-privileged-action" or value == "block"
            ):
                signals.append(SessionSignal("injection", WEIGHTS["injection"], "injection indicators on this call",
                                             request.action))
            if value in {"require_approval", "escalate_to_human"}:
                signals.append(SessionSignal("human_hold", WEIGHTS["human_hold"], decision.reason, request.action))
            recent = sum(1 for t in state.timestamps if now - t <= 60)
            if recent > VELOCITY_LIMIT:
                signals.append(SessionSignal("velocity", WEIGHTS["velocity"], f"{recent} actions in 60s", request.action))
            state.signals.extend(signals)
            state.risk = round(state.risk + sum(s.weight for s in signals), 2)
            state.last_action = request.action
            state.elevated = state.risk >= self.elevate_at
            if state.risk < self.trip_at:
                return None
            state.tripped = True
            state.tripped_at = datetime.now(timezone.utc).isoformat()
            return self._on_trip(state)

    def _on_trip(self, state: SessionState) -> dict:
        trips = self._trips.setdefault(state.agent_id, deque())
        now = time.monotonic()
        trips.append(now)
        while trips and now - trips[0] > self.window_seconds:
            trips.popleft()
        suspended = False
        if len(trips) >= self.suspend_after and self.registry is not None:
            agent = self.registry.get(state.agent_id)
            if agent is not None and agent.status.value == "active":
                self.registry.suspend(state.agent_id)
                suspended = True
        event = {"session_id": state.session_id, "agent_id": state.agent_id, "agent_version": state.agent_key,
                 "tenant_id": state.tenant_id, "risk": state.risk, "tripped_at": state.tripped_at,
                 "trips_in_window": len(trips), "agent_suspended": suspended,
                 "top_signals": [s.__dict__ for s in sorted(state.signals, key=lambda s: -s.weight)[:5]]}
        self._quarantine_log.append(event)
        if self.audit is not None:
            self.audit.append(agent_id=state.agent_id, action="session.circuit_breaker", target=state.session_id,
                              decision="block", risk_score=min(100.0, state.risk),
                              reason=f"Session risk {state.risk:.0f} crossed the circuit-breaker threshold.",
                              risk_factors=[s.kind for s in state.signals], event_type="session.circuit_breaker",
                              policy_id="session-circuit-breaker", trace_id=state.session_id, tenant_id=state.tenant_id)
            if suspended:
                self.audit.append(agent_id=state.agent_id, action="agent.quarantined", target=state.agent_id,
                                  decision="block", risk_score=100.0,
                                  reason=f"Agent tripped the circuit breaker {len(trips)} times in "
                                         f"{self.window_seconds // 60} minutes and was suspended.",
                                  event_type="agent.quarantined", policy_id="agent-kill-switch",
                                  trace_id=state.session_id, tenant_id=state.tenant_id)
        return event

    def reset_trips(self, agent_id: str) -> None:
        self._trips.pop(agent_id, None)

    # ------------------------------------------------------------------ queries
    def list(self, limit: int = 100, tripped_only: bool = False, min_risk: float = 0) -> list[dict]:
        items = [s for s in reversed(self._sessions.values()) if s.risk >= min_risk and (s.tripped or not tripped_only)]
        items.sort(key=lambda s: (-s.tripped, -s.risk))
        return [s.to_dict() for s in items[:limit]]

    def quarantine_log(self) -> list[dict]:
        return list(reversed(self._quarantine_log))

    def stats(self) -> dict:
        sessions = list(self._sessions.values())
        return {
            "sessions": len(sessions),
            "elevated": sum(s.elevated and not s.tripped for s in sessions),
            "tripped": sum(s.tripped for s in sessions),
            "agents_suspended_by_guard": sum(1 for e in self._quarantine_log if e["agent_suspended"]),
            "thresholds": {"elevate_at": self.elevate_at, "trip_at": self.trip_at, "suspend_after": self.suspend_after,
                           "window_seconds": self.window_seconds},
            "models": {key: {"sequences": m.sequences, "actions": len(m.vocabulary)} for key, m in self.models.items()},
        }

    def describe_model(self, agent_key: str) -> dict[str, Any] | None:
        model = self.models.get(agent_key)
        return model.describe() if model else None
