"""Safe policy change management: decision log, shadow mode, impact analysis, canary rollout.

Changing an authorization policy is a production change with security consequences in both
directions: too loose lets money move, too strict breaks support. Nothing here enforces a
candidate pack until an operator promotes it.

* **Decision log** - every enforced decision keeps the *policy inputs* (action, tenant,
  ownership, redacted arguments, effective risk, findings, injection and session signals and
  the baseline decision). Raw content and credentials are never stored.
* **Replay / impact analysis** - re-evaluate the log (and, optionally, the full evaluation
  suite) under the live pack and a candidate pack and report every flip, classified as
  *tightening* or *relaxation*, per-rule hit counts, dead rules, a structural diff and
  release-gate deltas. Relaxations always need explicit acknowledgement to promote.
* **Shadow mode** - a candidate pack is evaluated beside the live pack on real traffic; its
  decision is recorded, never enforced.
* **Canary** - a candidate pack *is* enforced for selected tenants and/or a deterministic
  percentage of sessions, with per-pack decision statistics and an automatic rollback guard.
"""

from __future__ import annotations

import hashlib
from collections import Counter, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from threading import Lock
from typing import Any
from uuid import uuid4

from app.domain import ActionRequest, Decision, DecisionResponse
from app.policy_engine import _PRECEDENCE, PolicyContext, PolicyEngine, PolicyRule

STRICTNESS = {d.value: rank for d, rank in _PRECEDENCE.items()}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class DecisionRecord:
    record_id: str
    at: str
    agent_id: str
    tenant_id: str | None
    action: str
    target: str
    request: dict            # ActionRequest without content or credential secrets; payload already redacted
    risk_score: float
    findings: list[str]
    injection_score: int
    injection_detected: bool
    session_risk: float
    baseline: dict           # baseline DecisionResponse (decision, reason, risk...)
    live_decision: str
    live_policy_id: str | None
    pack_version: str
    shadow_decision: str | None = None
    shadow_policy_id: str | None = None
    source: str = "live"     # live | evaluation

    def context(self) -> PolicyContext:
        return PolicyContext(
            request=ActionRequest(**self.request), risk_score=self.risk_score, findings=tuple(self.findings),
            injection_score=self.injection_score, injection_detected=self.injection_detected,
            session_risk=self.session_risk,
        )

    def summary(self) -> dict:
        args = self.request.get("execution_payload") or {}
        return {"record_id": self.record_id, "at": self.at, "action": self.action, "target": self.target,
                "tenant_id": self.tenant_id, "user_role": self.request.get("user_role"),
                "amount": args.get("amount"), "risk": round(self.risk_score, 1), "source": self.source}


def make_record(request: ActionRequest, ctx: PolicyContext, baseline: DecisionResponse, live: DecisionResponse,
                pack_version: str, redacted_payload: dict, source: str = "live") -> DecisionRecord:
    stored = request.model_dump(exclude={"content", "credential_token", "credential_id", "approval_id"})
    stored["execution_payload"] = redacted_payload
    return DecisionRecord(
        record_id=f"dec_{uuid4().hex[:12]}", at=_now(), agent_id=request.agent_id, tenant_id=request.tenant_id,
        action=request.action, target=request.target, request=stored, risk_score=ctx.risk_score,
        findings=list(ctx.findings), injection_score=ctx.injection_score, injection_detected=ctx.injection_detected,
        session_risk=ctx.session_risk, baseline=baseline.model_dump(mode="json"), live_decision=live.decision.value,
        live_policy_id=live.policy_id, pack_version=pack_version, source=source,
    )


def static_engine(engine: PolicyEngine) -> PolicyEngine:
    """Copy without rate-limit rules: replay must not depend on (or consume) live counters."""
    return PolicyEngine([r for r in engine.rules if r.decision != Decision.RATE_LIMIT], engine.version)


def decide(record: DecisionRecord, engine: PolicyEngine) -> tuple[str, str | None, list[str]]:
    """Re-run the gateway's merge (baseline + rules, strictest wins) for a recorded request."""
    from app.gateway import ToolGateway  # local import: gateway imports this module's callers

    baseline = DecisionResponse(**record.baseline)
    outcome = engine.evaluate(record.context())
    merged = ToolGateway._merge(baseline, outcome)
    return merged.decision.value, merged.policy_id, list(merged.matched_policies)


def diff_packs(live: list[PolicyRule], candidate: list[PolicyRule]) -> dict:
    a = {r.id: r.model_dump(mode="json") for r in live}
    b = {r.id: r.model_dump(mode="json") for r in candidate}
    changed = []
    for rid in sorted(set(a) & set(b)):
        if a[rid] != b[rid]:
            fields = sorted(k for k in set(a[rid]) | set(b[rid]) if a[rid].get(k) != b[rid].get(k))
            changed.append({"id": rid, "fields": fields, "before": {k: a[rid].get(k) for k in fields},
                            "after": {k: b[rid].get(k) for k in fields}})
    return {"added": sorted(set(b) - set(a)), "removed": sorted(set(a) - set(b)), "changed": changed}


def replay(records: list[DecisionRecord], live: PolicyEngine, candidate: PolicyEngine, example_limit: int = 15) -> dict:
    live_s, cand_s = static_engine(live), static_engine(candidate)
    transitions: Counter = Counter()
    rule_hits: Counter = Counter()
    tightening, relaxation = [], []
    for record in records:
        before, before_policy, _ = decide(record, live_s)
        after, after_policy, matched = decide(record, cand_s)
        rule_hits.update(matched)
        transitions[(before, after)] += 1
        if before == after:
            continue
        item = {**record.summary(), "before": before, "after": after,
                "before_policy": before_policy, "after_policy": after_policy}
        (tightening if STRICTNESS[after] > STRICTNESS[before] else relaxation).append(item)
    matrix: dict[str, dict[str, int]] = {}
    for (before, after), count in sorted(transitions.items()):
        matrix.setdefault(before, {})[after] = count
    unchanged = sum(c for (b, a), c in transitions.items() if b == a)
    return {
        "records": len(records),
        "unchanged": unchanged,
        "agreement_rate": round(unchanged / len(records), 4) if records else None,
        "tightened": len(tightening),
        "relaxed": len(relaxation),
        "transitions": matrix,
        "relaxation_examples": relaxation[:example_limit],
        "tightening_examples": tightening[:example_limit],
        "rule_hits": dict(rule_hits.most_common()),
        "dead_rules": sorted(r.id for r in candidate.rules if r.id not in rule_hits and r.decision != Decision.RATE_LIMIT),
    }


@dataclass
class Canary:
    engine: PolicyEngine
    tenants: set[str]
    percent: int
    started_at: str = field(default_factory=_now)
    auto_rollback: bool = True
    max_strictness_shift: float = 0.30   # rollback when canary hold/block rate differs this much from live
    min_decisions: int = 20
    counts: dict[str, Counter] = field(default_factory=lambda: {"canary": Counter(), "live": Counter()})

    def selects(self, request: ActionRequest) -> bool:
        if request.tenant_id and request.tenant_id in self.tenants:
            return True
        if self.percent <= 0:
            return False
        key = request.correlation_id or f"{request.tenant_id}:{request.agent_id}"
        bucket = int(hashlib.sha256(key.encode()).hexdigest()[:8], 16) % 100
        return bucket < self.percent

    def health(self) -> dict:
        def rates(counter: Counter) -> dict:
            total = sum(counter.values())
            held = counter["require_approval"] + counter["escalate_to_human"]
            stopped = counter["block"] + counter["rate_limit"]
            return {"decisions": total, "hold_rate": round(held / total, 4) if total else None,
                    "block_rate": round(stopped / total, 4) if total else None, "by_decision": dict(counter)}
        canary, live = rates(self.counts["canary"]), rates(self.counts["live"])
        shift = None
        if canary["decisions"] and live["decisions"]:
            shift = round(((canary["hold_rate"] or 0) + (canary["block_rate"] or 0))
                          - ((live["hold_rate"] or 0) + (live["block_rate"] or 0)), 4)
        anomalous = bool(shift is not None and canary["decisions"] >= self.min_decisions
                         and abs(shift) > self.max_strictness_shift)
        return {"canary": canary, "live": live, "strictness_shift": shift, "anomalous": anomalous}


class PolicyRollout:
    def __init__(self, capacity: int = 10_000, audit=None) -> None:
        self.log: deque[DecisionRecord] = deque(maxlen=capacity)
        self.shadow: PolicyEngine | None = None
        self.shadow_started_at: str | None = None
        self.shadow_stats: Counter = Counter()
        self.shadow_disagreements: deque[dict] = deque(maxlen=500)
        self.canary: Canary | None = None
        self.history: list[dict] = []
        self.audit = audit
        self._lock = Lock()

    # ---------------------------------------------------------------- recording
    def record(self, record: DecisionRecord) -> None:
        with self._lock:
            self.log.append(record)
            if record.shadow_decision is not None:
                self.shadow_stats[(record.live_decision, record.shadow_decision)] += 1
                if record.shadow_decision != record.live_decision:
                    direction = "tighter" if STRICTNESS[record.shadow_decision] > STRICTNESS[record.live_decision] else "looser"
                    self.shadow_disagreements.append({**record.summary(), "live": record.live_decision,
                                                      "shadow": record.shadow_decision, "direction": direction,
                                                      "live_policy": record.live_policy_id,
                                                      "shadow_policy": record.shadow_policy_id})

    def engine_for(self, request: ActionRequest, live: PolicyEngine) -> tuple[PolicyEngine, bool]:
        canary = self.canary
        if canary is not None and canary.selects(request):
            return canary.engine, True
        return live, False

    def count_canary(self, used_canary: bool, decision: str) -> dict | None:
        canary = self.canary
        if canary is None:
            return None
        canary.counts["canary" if used_canary else "live"][decision] += 1
        health = canary.health()
        if canary.auto_rollback and health["anomalous"]:
            self.rollback_canary(reason=f"automatic: strictness shift {health['strictness_shift']:+.0%}")
            return health
        return None

    # ---------------------------------------------------------------- shadow
    def start_shadow(self, engine: PolicyEngine) -> None:
        self.shadow = engine
        self.shadow_started_at = _now()
        self.shadow_stats = Counter()
        self.shadow_disagreements.clear()
        self._history("shadow_started", engine.version)

    def stop_shadow(self) -> None:
        if self.shadow is not None:
            self._history("shadow_stopped", self.shadow.version)
        self.shadow = None

    def shadow_report(self) -> dict:
        total = sum(self.shadow_stats.values())
        agree = sum(c for (a, b), c in self.shadow_stats.items() if a == b)
        matrix: dict[str, dict[str, int]] = {}
        for (live, shadow), count in sorted(self.shadow_stats.items()):
            matrix.setdefault(live, {})[shadow] = count
        return {
            "active": self.shadow is not None,
            "version": self.shadow.version if self.shadow else None,
            "started_at": self.shadow_started_at,
            "decisions": total,
            "agreement_rate": round(agree / total, 4) if total else None,
            "transitions": matrix,
            "looser": sum(1 for d in self.shadow_disagreements if d["direction"] == "looser"),
            "tighter": sum(1 for d in self.shadow_disagreements if d["direction"] == "tighter"),
            "disagreements": list(reversed(self.shadow_disagreements))[:50],
        }

    # ---------------------------------------------------------------- canary
    def start_canary(self, engine: PolicyEngine, tenants: list[str], percent: int, auto_rollback: bool = True) -> Canary:
        if not tenants and percent <= 0:
            raise ValueError("A canary needs at least one tenant or a percentage above 0")
        if not 0 <= percent <= 50:
            raise ValueError("Canary percentage must be between 0 and 50; promote instead of canarying more")
        self.canary = Canary(engine, set(tenants), percent, auto_rollback=auto_rollback)
        self._history("canary_started", engine.version, tenants=sorted(tenants), percent=percent)
        return self.canary

    def rollback_canary(self, reason: str = "manual") -> None:
        if self.canary is not None:
            self._history("canary_rolled_back", self.canary.engine.version, reason=reason,
                          health=self.canary.health())
            if self.audit is not None:
                self.audit.append(agent_id="sentinelforge", action="policy.canary.rollback",
                                  target=self.canary.engine.version, decision="block", risk_score=0,
                                  reason=f"Canary rolled back ({reason}).", event_type="policy.rollout")
        self.canary = None

    def canary_status(self) -> dict | None:
        if self.canary is None:
            return None
        return {"version": self.canary.engine.version, "tenants": sorted(self.canary.tenants),
                "percent": self.canary.percent, "started_at": self.canary.started_at,
                "auto_rollback": self.canary.auto_rollback, **self.canary.health()}

    # ---------------------------------------------------------------- misc
    def _history(self, event: str, version: str, **extra: Any) -> None:
        self.history.append({"event": event, "version": version, "at": _now(), **extra})

    def records(self, source: str | None = None) -> list[DecisionRecord]:
        return [r for r in self.log if source is None or r.source == source]

    def stats(self) -> dict:
        return {"decision_log": len(self.log), "shadow": self.shadow.version if self.shadow else None,
                "canary": self.canary.engine.version if self.canary else None,
                "events": list(reversed(self.history))[:20]}


def record_dict(record: DecisionRecord) -> dict:
    return asdict(record)
