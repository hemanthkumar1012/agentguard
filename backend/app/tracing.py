"""Agent run tracing: traces, spans, latency, tokens and cost.

Every agent run is one trace. Spans record LLM calls, retrievals, policy checks,
tool executions, approvals and sub-agent hand-offs. When `opentelemetry-api` is
installed, spans are mirrored to OpenTelemetry so they can be exported to any OTLP
backend; the in-process store is what powers the trace explorer.
"""

from __future__ import annotations

import time
from collections import OrderedDict
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from threading import Lock
from typing import Any, Iterator
from uuid import uuid4

try:  # Optional: OpenTelemetry API is a no-op unless an SDK/exporter is configured.
    from opentelemetry import trace as _otel_trace

    _tracer = _otel_trace.get_tracer("sentinelforge.agent")
except Exception:  # pragma: no cover - optional dependency
    _tracer = None


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class Span:
    span_id: str
    trace_id: str
    parent_id: str | None
    kind: str  # agent | llm | retrieval | policy | tool | approval | guard | handoff
    name: str
    started_at: datetime
    ended_at: datetime | None = None
    duration_ms: float = 0.0
    status: str = "ok"  # ok | blocked | error | pending
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["started_at"] = self.started_at.isoformat()
        data["ended_at"] = self.ended_at.isoformat() if self.ended_at else None
        return data


@dataclass
class Trace:
    trace_id: str
    tenant_id: str | None
    user_id: str | None
    agent_id: str | None
    agent_version: str | None
    model: str | None
    prompt_version: str | None
    input: str
    started_at: datetime
    ended_at: datetime | None = None
    status: str = "running"  # running | completed | blocked | awaiting_approval | failed | budget_exceeded
    output: str | None = None
    spans: list[Span] = field(default_factory=list)
    tags: dict[str, Any] = field(default_factory=dict)
    _t0: float = field(default_factory=time.perf_counter, repr=False)

    @property
    def duration_ms(self) -> float:
        if self.ended_at is None:
            return round((time.perf_counter() - self._t0) * 1000, 2)
        return round((self.ended_at - self.started_at).total_seconds() * 1000, 2)

    @property
    def active_ms(self) -> float:
        """Time the system spent working: root spans only, so human approval waits are excluded."""
        return round(sum(s.duration_ms for s in self.spans if s.parent_id is None), 3)

    def totals(self) -> dict:
        llm = [s for s in self.spans if s.kind == "llm"]
        tools = [s for s in self.spans if s.kind == "tool"]
        policy = [s for s in self.spans if s.kind == "policy"]
        decisions: dict[str, int] = {}
        for span in policy:
            decision = span.attributes.get("decision", "unknown")
            decisions[decision] = decisions.get(decision, 0) + 1
        return {
            "input_tokens": sum(int(s.attributes.get("input_tokens", 0)) for s in llm),
            "output_tokens": sum(int(s.attributes.get("output_tokens", 0)) for s in llm),
            "cost_inr": round(sum(float(s.attributes.get("cost_inr", 0)) for s in llm), 6),
            "llm_calls": len(llm),
            "tool_calls": len(tools),
            "tool_errors": sum(s.status == "error" for s in tools),
            "policy_checks": len(policy),
            "decisions": decisions,
            "blocked_actions": sum(s.status == "blocked" for s in policy),
            "max_risk": max((float(s.attributes.get("risk_score", 0)) for s in policy), default=0.0),
        }

    def summary(self) -> dict:
        totals = self.totals()
        return {
            "trace_id": self.trace_id,
            "tenant_id": self.tenant_id,
            "user_id": self.user_id,
            "agent_id": self.agent_id,
            "agent_version": self.agent_version,
            "model": self.model,
            "status": self.status,
            "input": self.input[:200],
            "started_at": self.started_at.isoformat(),
            "duration_ms": self.duration_ms,
            "active_ms": self.active_ms,
            "tools": sorted({s.name for s in self.spans if s.kind == "policy"}),
            "policies": sorted({p for s in self.spans for p in s.attributes.get("matched_policies", [])}),
            **totals,
        }

    def to_dict(self) -> dict:
        return {
            **self.summary(),
            "input": self.input,
            "output": self.output,
            "prompt_version": self.prompt_version,
            "ended_at": self.ended_at.isoformat() if self.ended_at else None,
            "tags": self.tags,
            "spans": [s.to_dict() for s in self.spans],
        }


class TraceStore:
    def __init__(self, capacity: int = 2000, store=None) -> None:
        self.capacity = capacity
        self.store = store
        self._traces: "OrderedDict[str, Trace]" = OrderedDict()
        self._lock = Lock()

    # ---------------------------------------------------------------- lifecycle
    def start(self, *, input: str, tenant_id=None, user_id=None, agent_id=None, agent_version=None,
              model=None, prompt_version=None, tags: dict | None = None, trace_id: str | None = None) -> Trace:
        trace = Trace(
            trace_id=trace_id or f"trc_{uuid4().hex[:16]}",
            tenant_id=tenant_id, user_id=user_id, agent_id=agent_id, agent_version=agent_version,
            model=model, prompt_version=prompt_version, input=input, started_at=_now(), tags=dict(tags or {}),
        )
        with self._lock:
            self._traces[trace.trace_id] = trace
            while len(self._traces) > self.capacity:
                self._traces.popitem(last=False)
        return trace

    def finish(self, trace: Trace, status: str, output: str | None = None) -> Trace:
        trace.status = status
        trace.output = output
        trace.ended_at = _now()
        if self.store is not None and hasattr(self.store, "upsert_trace"):
            try:
                self.store.upsert_trace(trace.to_dict())
            except Exception:  # pragma: no cover - persistence is best-effort for traces
                trace.tags["persistence_error"] = True
        return trace

    @contextmanager
    def span(self, trace: Trace, kind: str, name: str, parent_id: str | None = None, **attributes) -> Iterator[Span]:
        span = Span(f"spn_{uuid4().hex[:12]}", trace.trace_id, parent_id, kind, name, _now(), attributes=dict(attributes))
        t0 = time.perf_counter()
        otel_cm = _tracer.start_as_current_span(f"{kind}:{name}") if _tracer is not None else None
        otel_span = otel_cm.__enter__() if otel_cm is not None else None
        try:
            yield span
        except Exception as exc:
            span.status = "error"
            span.attributes["error"] = type(exc).__name__
            raise
        finally:
            span.duration_ms = round((time.perf_counter() - t0) * 1000, 3)
            span.ended_at = _now()
            trace.spans.append(span)
            if otel_span is not None:
                for key, value in span.attributes.items():
                    if isinstance(value, (str, bool, int, float)):
                        otel_span.set_attribute(f"sentinelforge.{key}", value)
                otel_span.set_attribute("sentinelforge.status", span.status)
                otel_cm.__exit__(None, None, None)

    # ------------------------------------------------------------------ queries
    def get(self, trace_id: str) -> Trace | None:
        return self._traces.get(trace_id)

    def list(self, *, tenant_id=None, agent_version=None, agent_id=None, user_id=None, status=None,
             tool=None, policy=None, limit: int = 100) -> list[dict]:
        out = []
        for trace in reversed(list(self._traces.values())):
            summary = trace.summary()
            if tenant_id and trace.tenant_id != tenant_id:
                continue
            if agent_version and trace.agent_version != agent_version:
                continue
            if agent_id and trace.agent_id != agent_id:
                continue
            if user_id and trace.user_id != user_id:
                continue
            if status and trace.status != status:
                continue
            if tool and tool not in summary["tools"]:
                continue
            if policy and policy not in summary["policies"]:
                continue
            out.append(summary)
            if len(out) >= limit:
                break
        return out

    def all(self) -> list[Trace]:
        return list(self._traces.values())

    def stats(self) -> dict:
        traces = [t for t in self._traces.values() if not t.tags.get("evaluation")]
        if not traces:
            return {"runs": 0, "by_status": {}, "avg_latency_ms": 0, "p95_latency_ms": 0, "total_cost_inr": 0,
                    "total_tokens": 0, "tool_errors": 0, "blocked_actions": 0, "by_version": {}, "risk_trend": []}
        finished = [t for t in traces if t.ended_at is not None] or traces
        latencies = sorted(t.active_ms for t in finished)
        by_status: dict[str, int] = {}
        by_version: dict[str, dict] = {}
        totals_cache = {t.trace_id: t.totals() for t in traces}
        for trace in traces:
            by_status[trace.status] = by_status.get(trace.status, 0) + 1
            version = by_version.setdefault(trace.agent_version or "unknown", {"runs": 0, "blocked_actions": 0, "cost_inr": 0.0})
            version["runs"] += 1
            version["blocked_actions"] += totals_cache[trace.trace_id]["blocked_actions"]
            version["cost_inr"] = round(version["cost_inr"] + totals_cache[trace.trace_id]["cost_inr"], 6)
        trend = [
            {"trace_id": t.trace_id, "started_at": t.started_at.isoformat(), "max_risk": totals_cache[t.trace_id]["max_risk"],
             "agent_version": t.agent_version}
            for t in traces[-50:]
        ]
        return {
            "runs": len(traces),
            "by_status": by_status,
            "latency_basis": "agent processing time (excludes human approval waits)",
            "avg_latency_ms": round(sum(latencies) / len(latencies), 2),
            "p95_latency_ms": latencies[min(len(latencies) - 1, int(len(latencies) * 0.95))],
            "total_cost_inr": round(sum(v["cost_inr"] for v in totals_cache.values()), 4),
            "total_tokens": sum(v["input_tokens"] + v["output_tokens"] for v in totals_cache.values()),
            "tool_errors": sum(v["tool_errors"] for v in totals_cache.values()),
            "blocked_actions": sum(v["blocked_actions"] for v in totals_cache.values()),
            "by_version": by_version,
            "risk_trend": trend,
        }
