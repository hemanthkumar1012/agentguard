"use client";

import { useEffect, useMemo, useState } from "react";
import { RefreshCw } from "lucide-react";
import { Span, TraceDetail, TraceSummary, inr, sfGet } from "../../lib/sf";
import { DecisionPill, ErrorNote, KV, PageHeader, PanelHead, StatusPill } from "./ui";

const KIND_LABEL: Record<string, string> = {
  llm: "LLM", policy: "POLICY", tool: "TOOL", retrieval: "RAG", approval: "HUMAN", guard: "GUARD", agent: "AGENT", handoff: "HANDOFF",
};

export function TraceExplorer({ initialTraceId }: { initialTraceId?: string | null }) {
  const [traces, setTraces] = useState<TraceSummary[]>([]);
  const [filters, setFilters] = useState({ agent_version: "", status: "", policy: "", include_evaluations: "" });
  const [selected, setSelected] = useState<string | null>(initialTraceId ?? null);
  const [detail, setDetail] = useState<TraceDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    try {
      const body = await sfGet<{ traces: TraceSummary[] }>("traces", { ...filters, limit: "100" });
      setTraces(body.traces);
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    }
  }

  useEffect(() => { load(); }, [filters]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { if (initialTraceId) setSelected(initialTraceId); }, [initialTraceId]);
  useEffect(() => {
    if (!selected) return;
    sfGet<TraceDetail>(`traces/${selected}`).then(setDetail).catch((e) => setError(e.message));
  }, [selected]);

  return (
    <>
      <PageHeader eyebrow="OBSERVABILITY" title="Trace Explorer"
        sub="Every agent run, from input to final answer: model calls, retrieved documents, policy checks, tool calls, approvals, cost.">
        <button onClick={load}><RefreshCw size={16} /> Refresh</button>
      </PageHeader>

      <section className="panel">
        <div className="filters">
          <input placeholder="Agent version" value={filters.agent_version} onChange={(e) => setFilters({ ...filters, agent_version: e.target.value })} />
          <select value={filters.status} onChange={(e) => setFilters({ ...filters, status: e.target.value })}>
            <option value="">Any status</option>
            {["completed", "completed_with_blocks", "awaiting_approval", "budget_exceeded", "failed"].map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <input placeholder="Policy id (e.g. refund-above-threshold)" value={filters.policy} onChange={(e) => setFilters({ ...filters, policy: e.target.value })} />
          <label className="check"><input type="checkbox" checked={!!filters.include_evaluations}
            onChange={(e) => setFilters({ ...filters, include_evaluations: e.target.checked ? "true" : "" })} /> Include evaluation runs</label>
        </div>
        <ErrorNote error={error} />
        {traces.length === 0 ? <div className="empty">No traces yet. Run the playground or an evaluation.</div> : (
          <div className="data-list compact">
            {traces.map((t) => (
              <button key={t.trace_id} className={`data-row clickable ${selected === t.trace_id ? "selected" : ""}`} onClick={() => setSelected(t.trace_id)}>
                <div><b>{t.input.slice(0, 80)}</b><span>{t.trace_id} · {t.agent_version} · {t.user_id ?? "anonymous"}</span></div>
                <StatusPill status={t.status} />
                <span>{t.tool_calls} tools · {t.blocked_actions} blocked</span>
                <small>{t.duration_ms.toFixed(1)} ms · {inr(t.cost_inr)}</small>
              </button>
            ))}
          </div>
        )}
      </section>

      {detail && <TraceDetailView trace={detail} />}
    </>
  );
}

function TraceDetailView({ trace }: { trace: TraceDetail }) {
  const total = Math.max(1, trace.spans.reduce((sum, s) => sum + s.duration_ms, 0));
  const started = useMemo(() => new Date(trace.started_at).getTime(), [trace.started_at]);
  return (
    <>
      <section className="panel">
        <PanelHead eyebrow="RUN" title={trace.trace_id} badge={trace.status.replaceAll("_", " ").toUpperCase()} />
        <div className="kv-row">
          <KV label="Agent">{trace.agent_version}</KV>
          <KV label="Model">{trace.model}{trace.tags?.planner === "scripted" ? " (simulated)" : ""}</KV>
          <KV label="Prompt">{trace.prompt_version}</KV>
          <KV label="Tenant / user">{trace.tenant_id} / {trace.user_id}</KV>
          <KV label="Latency">{trace.duration_ms.toFixed(1)} ms</KV>
          <KV label="Tokens">{(trace.input_tokens + trace.output_tokens).toLocaleString()}</KV>
          <KV label="Cost">{inr(trace.cost_inr)}</KV>
          <KV label="Max risk">{Math.round(trace.max_risk)}</KV>
        </div>
        <div className="two-col">
          <div><p className="eyebrow">INPUT</p><blockquote className="answer">{trace.input}</blockquote></div>
          <div><p className="eyebrow">OUTPUT</p><blockquote className="answer">{trace.output ?? "—"}</blockquote></div>
        </div>
      </section>

      <section className="panel">
        <PanelHead eyebrow="TIMELINE" title="Spans" badge={`${trace.spans.length} SPANS`} />
        <div className="timeline">
          {trace.spans.map((span) => <SpanRow key={span.span_id} span={span} total={total} offset={new Date(span.started_at).getTime() - started} />)}
        </div>
      </section>

      <div className="grid">
        <section className="panel">
          <PanelHead eyebrow="AUDIT" title="Hash-chained events" badge={`${trace.audit_events.length}`} />
          {trace.audit_events.length === 0 ? <div className="empty">No audit events for this trace (evaluation runs audit in their sandbox).</div> : (
            <div className="data-list compact">
              {trace.audit_events.map((e) => (
                <div className="data-row" key={e.event_id}>
                  <div><b>{e.event_id}</b><span>{e.reason}</span></div>
                  <DecisionPill decision={e.decision} />
                  <small><code>{e.policy_id}</code></small>
                  <small title={e.event_hash}><code>{e.event_hash.slice(0, 16)}…</code></small>
                </div>
              ))}
            </div>
          )}
        </section>
        <section className="panel">
          <PanelHead eyebrow="WHY" title="Policies that fired" />
          {trace.policies.length === 0 ? <div className="empty">No declarative policy matched.</div> : (
            <div className="chips">{trace.policies.map((p) => <span className="chip static" key={p}>{p}</span>)}</div>
          )}
          {trace.approvals.length > 0 && (
            <div className="data-list compact">
              {trace.approvals.map((a) => (
                <div className="data-row" key={a.approval_id}>
                  <div><b>{a.action}</b><span>{a.approval_id} · {a.approver_role}</span></div>
                  <StatusPill status={a.status} />
                  <small>{a.decided_by ?? "awaiting decision"}</small>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>
    </>
  );
}

function SpanRow({ span, total, offset }: { span: Span; total: number; offset: number }) {
  const [open, setOpen] = useState(false);
  const a = span.attributes;
  const width = Math.max(2, (span.duration_ms / total) * 100);
  return (
    <div className={`span-row ${span.status}`}>
      <button className="span-head" onClick={() => setOpen(!open)}>
        <span className={`kind kind-${span.kind}`}>{KIND_LABEL[span.kind] ?? span.kind}</span>
        <span className="span-name">{span.name}</span>
        {a.decision && <DecisionPill decision={a.decision} />}
        {a.agent_id && span.kind === "agent" && <small>{a.agent_id}</small>}
        <span className="bar"><i style={{ width: `${width}%` }} /></span>
        <small>{span.duration_ms.toFixed(2)} ms · +{Math.max(0, offset)} ms</small>
      </button>
      {open && (
        <div className="span-body">
          {a.reason && <KV label="Reason">{a.reason}</KV>}
          {a.policy_id && <KV label="Policy">{a.policy_id}</KV>}
          {a.matched_policies?.length > 0 && <KV label="Matched">{a.matched_policies.join(", ")}</KV>}
          {a.risk_score !== undefined && <KV label="Risk">{Math.round(a.risk_score)} · {(a.risk_factors ?? []).join(", ") || "no factors"}</KV>}
          {a.content_source && <KV label="Content source">{a.content_source}{a.derived_from_untrusted ? " (call derived from untrusted text)" : ""}</KV>}
          {a.arguments && <KV label="Arguments"><code>{a.arguments}</code></KV>}
          {a.input_tokens !== undefined && <KV label="Tokens">{a.input_tokens} in / {a.output_tokens} out · {inr(a.cost_inr)}</KV>}
          {a.doc_ids && <KV label="Documents">{a.doc_ids.join(", ")}</KV>}
          {a.output_preview && <KV label="Output"><code>{a.output_preview}</code></KV>}
          {a.redactions && <KV label="Redacted">{a.redactions.join(", ")}</KV>}
          {a.error && <KV label="Error">{String(a.error)}</KV>}
          {a.intents && <KV label="Intents → route">{a.intents.join(", ")} → {(a.route ?? []).join(" → ")}</KV>}
        </div>
      )}
    </div>
  );
}
