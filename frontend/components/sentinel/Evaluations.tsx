"use client";

import { useEffect, useState } from "react";
import { ArrowUpCircle, FlaskConical, GitCompare } from "lucide-react";
import { AgentVersion, CaseResult, EvaluationBrief, METRIC_LABELS, inr, pct, sfGet, sfPost } from "../../lib/sf";
import { ErrorNote, PageHeader, PanelHead, StatusPill, TraceLink } from "./ui";

type Comparison = {
  metric_deltas: Record<string, { baseline: number | null; candidate: number | null; delta: number | null }>;
  regressions: { case_id: string; dataset: string; failures: string[]; candidate_trace: string }[];
  fixes: { case_id: string; dataset: string }[];
};

function formatMetric(metric: string, value: number | null | undefined) {
  if (metric === "avg_cost_per_task_inr") return inr(value);
  if (metric === "p95_latency_ms") return value === null || value === undefined ? "—" : `${value.toFixed(1)} ms`;
  return pct(value);
}

export function Evaluations({ onOpenTrace }: { onOpenTrace: (id: string) => void }) {
  const [versions, setVersions] = useState<AgentVersion[]>([]);
  const [runs, setRuns] = useState<EvaluationBrief[]>([]);
  const [selected, setSelected] = useState<(EvaluationBrief & { cases: CaseResult[] }) | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [baseline, setBaseline] = useState("");
  const [candidate, setCandidate] = useState("");
  const [comparison, setComparison] = useState<Comparison | null>(null);
  const [datasets, setDatasets] = useState<{ name: string; cases: number }[]>([]);

  async function load() {
    try {
      const [v, r, d] = await Promise.all([
        sfGet<{ versions: AgentVersion[] }>("agent-versions"),
        sfGet<{ evaluations: EvaluationBrief[] }>("evaluations"),
        sfGet<{ datasets: { name: string; cases: number }[] }>("evaluations/datasets"),
      ]);
      setVersions(v.versions);
      setRuns(r.evaluations);
      setDatasets(d.datasets);
    } catch (e) {
      setError((e as Error).message);
    }
  }
  useEffect(() => { load(); }, []);

  async function open(id: string) {
    setSelected(await sfGet(`evaluations/${id}`, { failed_only: "true" }));
  }

  async function evaluate(versionId: string) {
    setBusy(versionId);
    setError(null);
    try {
      const run = await sfPost<EvaluationBrief>("evaluations", { version_id: versionId });
      await load();
      await open(run.evaluation_id);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(null);
    }
  }

  async function promote(versionId: string) {
    setError(null);
    try {
      await sfPost(`agent-versions/${versionId}/promote`);
      await load();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  async function compare() {
    setError(null);
    try {
      setComparison(await sfPost<Comparison>("evaluations/compare", { baseline_id: baseline, candidate_id: candidate }));
    } catch (e) {
      setError((e as Error).message);
    }
  }

  const totalCases = datasets.reduce((s, d) => s + d.cases, 0);
  return (
    <>
      <PageHeader eyebrow="RELEASE ENGINEERING" title="Evaluations & Release Gates"
        sub={`Run ${totalCases} versioned cases (${datasets.map((d) => d.name).join(", ")}) against an agent version. Critical gates block promotion.`} />
      <ErrorNote error={error} />

      <section className="panel">
        <PanelHead eyebrow="AGENT VERSIONS" title="Candidates and releases" />
        <div className="data-list">
          {versions.map((v) => (
            <div className="data-row" key={v.version_id}>
              <div><b>{v.version_id}</b><span>{v.description}</span></div>
              <StatusPill status={v.status} />
              <span>{v.model} · {v.prompt_version} · {v.planner}</span>
              <div className="row-gap">
                <button disabled={!!busy || v.planner === "openai"} onClick={() => evaluate(v.version_id)} title={v.planner === "openai" ? "Needs an LLM API key on the server" : ""}>
                  <FlaskConical size={14} /> {busy === v.version_id ? "Evaluating…" : "Evaluate"}
                </button>
                {v.status === "candidate" && <button className="primary" onClick={() => promote(v.version_id)}><ArrowUpCircle size={14} /> Promote</button>}
              </div>
            </div>
          ))}
        </div>
      </section>

      {selected && <Scorecard run={selected} onOpenTrace={onOpenTrace} />}

      <div className="grid">
        <section className="panel">
          <PanelHead eyebrow="HISTORY" title="Evaluation runs" badge={`${runs.length}`} />
          {runs.length === 0 ? <div className="empty">No evaluations yet.</div> : (
            <div className="data-list compact">
              {runs.map((r) => (
                <button className="data-row clickable" key={r.evaluation_id} onClick={() => open(r.evaluation_id)}>
                  <div><b>{r.version_id}</b><span>{r.evaluation_id} · {new Date(r.started_at).toLocaleTimeString()}</span></div>
                  <span className={`decision ${r.release_decision === "approved" ? "good" : "danger"}`}>{r.release_decision}</span>
                  <small>{r.summary.passed}/{r.summary.cases} passed</small>
                </button>
              ))}
            </div>
          )}
        </section>
        <section className="panel">
          <PanelHead eyebrow="REGRESSION" title="Compare two runs" />
          <div className="form">
            <select value={baseline} onChange={(e) => setBaseline(e.target.value)}>
              <option value="">Baseline run…</option>
              {runs.map((r) => <option key={r.evaluation_id} value={r.evaluation_id}>{r.version_id} · {r.evaluation_id}</option>)}
            </select>
            <select value={candidate} onChange={(e) => setCandidate(e.target.value)}>
              <option value="">Candidate run…</option>
              {runs.map((r) => <option key={r.evaluation_id} value={r.evaluation_id}>{r.version_id} · {r.evaluation_id}</option>)}
            </select>
            <button disabled={!baseline || !candidate} onClick={compare}><GitCompare size={14} /> Compare</button>
          </div>
          {comparison && (
            <>
              <div className="metric-table">
                {Object.entries(comparison.metric_deltas).map(([metric, d]) => (
                  <div key={metric}>
                    <span>{METRIC_LABELS[metric] ?? metric}</span>
                    <span>{formatMetric(metric, d.baseline)} → {formatMetric(metric, d.candidate)}</span>
                    <b className={d.delta === null || d.delta === 0 ? "" : (metric.includes("cost") || metric.includes("latency") ? d.delta < 0 : d.delta > 0) ? "good-text" : "danger-text"}>
                      {d.delta === null ? "" : `${d.delta > 0 ? "+" : ""}${metric.includes("cost") || metric.includes("latency") ? d.delta.toFixed(3) : (d.delta * 100).toFixed(1) + " pts"}`}
                    </b>
                  </div>
                ))}
              </div>
              <p className="hint">{comparison.regressions.length} regressions · {comparison.fixes.length} fixes</p>
              {comparison.regressions.slice(0, 10).map((r) => (
                <div className="callout danger" key={r.case_id}><b>{r.case_id}</b><span>{r.failures.join("; ")} · <TraceLink traceId={r.candidate_trace} onOpen={onOpenTrace} /></span></div>
              ))}
            </>
          )}
        </section>
      </div>
    </>
  );
}

function Scorecard({ run, onOpenTrace }: { run: EvaluationBrief & { cases: CaseResult[] }; onOpenTrace: (id: string) => void }) {
  const [expanded, setExpanded] = useState(false);
  const shown = expanded ? run.cases : run.cases.slice(0, 12);
  const approved = run.release_decision === "approved";
  return (
    <section className="panel">
      <PanelHead eyebrow={`SCORECARD · ${run.evaluation_id}`} title={`Version: ${run.version_id}`} />
      <div className={`release-banner ${approved ? "good" : "danger"}`}>
        Release decision: <b>{approved ? "APPROVED" : "BLOCKED"}</b> · {run.summary.passed}/{run.summary.cases} cases passed · total cost {inr(run.summary.total_cost_inr)}
      </div>
      <div className="gates">
        {run.gates.map((g) => (
          <div key={g.metric} className={`gate ${g.passed ? "pass" : g.critical ? "fail" : "warn"}`}>
            <span>{METRIC_LABELS[g.metric] ?? g.metric}</span>
            <b>{formatMetric(g.metric, g.value)}</b>
            <small>{g.comparator} {g.metric.includes("cost") ? inr(g.threshold) : g.metric.includes("latency") ? `${g.threshold} ms` : pct(g.threshold)} {g.passed ? "✓" : g.critical ? "✗ critical" : "✗"}</small>
          </div>
        ))}
      </div>
      <div className="chips">
        {Object.entries(run.summary.by_dataset).map(([name, b]) => (
          <span key={name} className="chip static">{name}: {b.passed}/{b.total}</span>
        ))}
      </div>
      {run.cases.length > 0 && (
        <>
          <p className="eyebrow" style={{ marginTop: 20 }}>FAILED CASES · EVIDENCE ({run.cases.length})</p>
          <div className="data-list compact">
            {shown.map((c) => (
              <div className="data-row case" key={c.case_id}>
                <div><b>{c.case_id} · {c.attack_type ?? c.dataset}</b><span>{c.failures.join("; ")}</span>{c.remediation && <span className="hint">Fix: {c.remediation}</span>}</div>
                <span className={`decision ${c.severity === "critical" ? "danger" : "warn"}`}>{c.severity}</span>
                <small>{c.attempted.map((a) => `${a.action}:${a.decision}`).join(", ") || "no tools"}</small>
                <TraceLink traceId={c.trace_id} onOpen={onOpenTrace} />
              </div>
            ))}
          </div>
          {run.cases.length > 12 && (
            <button className="link-button" onClick={() => setExpanded(!expanded)}>
              {expanded ? "Show fewer" : `Show all ${run.cases.length} failed cases`}
            </button>
          )}
        </>
      )}
    </section>
  );
}
