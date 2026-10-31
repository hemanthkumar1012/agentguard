"""Prometheus text exposition (format 0.0.4) without a client-library dependency."""

from __future__ import annotations

from collections import Counter


def _escape(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def _labels(**labels) -> str:
    if not labels:
        return ""
    return "{" + ",".join(f'{k}="{_escape(v)}"' for k, v in labels.items()) + "}"


LATENCY_BUCKETS_MS = (5, 25, 100, 250, 500, 1000, 2500, 5000, 10000)


def render(audit, traces, evaluations, approvals) -> str:
    lines: list[str] = []

    def metric(name: str, kind: str, help_text: str, samples: list[tuple[dict, float]]):
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} {kind}")
        for labels, value in samples:
            lines.append(f"{name}{_labels(**labels)} {value}")

    events = audit.list_events()
    decisions = Counter((e["decision"], e.get("policy_id") or "none") for e in events)
    metric("sentinelforge_gateway_decisions_total", "counter", "Gateway decisions by outcome and deciding policy.",
           [({"decision": d, "policy": p}, c) for (d, p), c in sorted(decisions.items())])
    metric("sentinelforge_audit_chain_valid", "gauge", "1 when the audit hash chain verifies.",
           [({}, 1 if audit.verify_integrity() else 0)])

    pending = sum(a.status in {"pending", "info_requested"} for a in approvals.list())
    metric("sentinelforge_approvals_pending", "gauge", "Approvals waiting for a human decision.", [({}, pending)])

    live = [t for t in traces.all() if not t.tags.get("evaluation")]
    status = Counter((t.agent_version or "unknown", t.status) for t in live)
    metric("sentinelforge_agent_runs_total", "counter", "Agent runs by version and final status.",
           [({"version": v, "status": s}, c) for (v, s), c in sorted(status.items())])

    tokens: Counter = Counter()
    cost: Counter = Counter()
    tool_calls: Counter = Counter()
    for trace in live:
        totals = trace.totals()
        tokens[trace.agent_version or "unknown"] += totals["input_tokens"] + totals["output_tokens"]
        cost[trace.agent_version or "unknown"] += totals["cost_inr"]
        for span in trace.spans:
            if span.kind == "tool":
                tool_calls[(span.name, span.status)] += 1
    metric("sentinelforge_llm_tokens_total", "counter", "LLM tokens consumed by agent version.",
           [({"version": v}, c) for v, c in sorted(tokens.items())])
    metric("sentinelforge_llm_cost_inr_total", "counter", "Estimated LLM cost in INR by agent version.",
           [({"version": v}, round(c, 6)) for v, c in sorted(cost.items())])
    metric("sentinelforge_tool_calls_total", "counter", "Executed tool calls by tool and status.",
           [({"tool": t, "status": s}, c) for (t, s), c in sorted(tool_calls.items())])

    lines.append("# HELP sentinelforge_agent_run_latency_ms Agent processing time per run (excludes approval waits).")
    lines.append("# TYPE sentinelforge_agent_run_latency_ms histogram")
    durations = [t.active_ms for t in live if t.ended_at is not None]
    for bucket in LATENCY_BUCKETS_MS:
        lines.append(f'sentinelforge_agent_run_latency_ms_bucket{{le="{bucket}"}} {sum(d <= bucket for d in durations)}')
    lines.append(f'sentinelforge_agent_run_latency_ms_bucket{{le="+Inf"}} {len(durations)}')
    lines.append(f"sentinelforge_agent_run_latency_ms_sum {round(sum(durations), 3)}")
    lines.append(f"sentinelforge_agent_run_latency_ms_count {len(durations)}")

    gate_samples = []
    for run in evaluations.list()[:20]:
        gate_samples.append(({"version": run["version_id"], "evaluation": run["evaluation_id"]},
                             1 if run["release_decision"] == "approved" else 0))
    metric("sentinelforge_release_gate_passed", "gauge", "1 when the evaluation approved the release.", gate_samples)
    return "\n".join(lines) + "\n"
