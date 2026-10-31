"use client";

import { useEffect, useState } from "react";
import { Dna, Download } from "lucide-react";
import { AgentVersion, downloadText, sfGet, sfGetText, sfPost } from "../../lib/sf";
import { ErrorNote, PanelHead, TraceLink } from "./ui";

type Bucket = { variants: number; detection: number; resistance: number; containment: number; attack_success: number };
type Brief = {
  goal: string; operators: string[]; source: string; detected: boolean; injection_score: number; resisted: boolean;
  contained: boolean; privacy: boolean; attempted: string[]; executed: string[]; trace_id: string; payload_preview: string;
  generation: number;
};
type FuzzSummary = {
  fuzz_id: string;
  version_id: string;
  params: { budget: number; generations: number; max_depth: number; elapsed_seconds?: number };
  totals: Bucket & { undetected: number; hijacked: number };
  by_operator: Record<string, Bucket>;
  single_operator: Record<string, Bucket>;
  by_depth: Record<string, Bucket>;
  by_goal: Record<string, Bucket>;
  generations: { generation: number; variants: number; evasion_rate: number; hijack_rate: number; success: number; best_fitness: number }[];
  weak_operators: { operator: string; detection: number }[];
  top_evasions: Brief[];
  successful_attacks: Brief[];
  detector: { benign_texts: number; flagged: number; false_positive_rate: number };
};

const pct = (v: number) => `${(v * 100).toFixed(1)}%`;

function Bars({ rows, metric }: { rows: [string, Bucket][]; metric: keyof Bucket }) {
  return (
    <div className="bars">
      {rows.map(([label, b]) => (
        <div className="bar-row" key={label}>
          <span>{label} <small className="muted-text">({b.variants})</small></span>
          <span className={`bar ${Number(b[metric]) < 0.8 ? "weak" : ""}`}><i style={{ width: `${Number(b[metric]) * 100}%` }} /></span>
          <small>{pct(Number(b[metric]))}</small>
        </div>
      ))}
    </div>
  );
}

export function FuzzLab({ onOpenTrace }: { onOpenTrace: (id: string) => void }) {
  const [versions, setVersions] = useState<AgentVersion[]>([]);
  const [versionId, setVersionId] = useState("support-agent-v2.0");
  const [budget, setBudget] = useState(600);
  const [generations, setGenerations] = useState(4);
  const [maxDepth, setMaxDepth] = useState(3);
  const [report, setReport] = useState<FuzzSummary | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [view, setView] = useState<"combined" | "single">("combined");

  useEffect(() => {
    sfGet<{ versions: AgentVersion[] }>("agent-versions")
      .then((b) => setVersions(b.versions.filter((v) => v.planner === "scripted")))
      .catch((e) => setError(e.message));
  }, []);

  async function run() {
    setBusy(true);
    setError(null);
    try {
      setReport(await sfPost<FuzzSummary>("redteam/fuzz", { version_id: versionId, budget, generations, max_depth: maxDepth }));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function exportCases(only: string) {
    if (!report) return;
    try {
      downloadText(`${report.fuzz_id}-${only}.jsonl`, await sfGetText(`redteam/fuzz/${report.fuzz_id}/cases`, { only }));
    } catch (e) {
      setError((e as Error).message);
    }
  }

  const operatorRows = Object.entries(view === "single" ? report?.single_operator ?? {} : report?.by_operator ?? {})
    .filter(([k]) => k !== "(none)")
    .sort((a, b) => a[1].detection - b[1].detection);
  return (
    <>
      <section className="panel">
        <PanelHead eyebrow="ADAPTIVE RED TEAM" title="Mutation fuzzer with evolutionary search" badge="SANDBOXED" />
        <p className="hint">
          Seeds (exfiltration, export, fraudulent refund, prompt leak, role hijack) are mutated with 13 operators (paraphrase,
          translation, homoglyphs, base64, zero-width, letter spacing, splitting across documents, role-play, authority, …),
          stacked up to the chosen depth and bred toward variants that evade detection or hijack the agent. Every variant runs
          through the real agent and gateway.
        </p>
        <div className="form inline">
          <select value={versionId} onChange={(e) => setVersionId(e.target.value)} aria-label="Agent version">
            {versions.map((v) => <option key={v.version_id} value={v.version_id}>{v.version_id}</option>)}
          </select>
          <label className="compact">Variants
            <select value={budget} onChange={(e) => setBudget(Number(e.target.value))}>
              {[200, 400, 600, 1000, 2000].map((n) => <option key={n} value={n}>{n}</option>)}
            </select>
          </label>
          <label className="compact">Generations
            <select value={generations} onChange={(e) => setGenerations(Number(e.target.value))}>
              {[0, 2, 4, 6, 8].map((n) => <option key={n} value={n}>{n}</option>)}
            </select>
          </label>
          <label className="compact">Max stack
            <select value={maxDepth} onChange={(e) => setMaxDepth(Number(e.target.value))}>
              {[1, 2, 3, 4].map((n) => <option key={n} value={n}>{n}</option>)}
            </select>
          </label>
          <button className="primary" disabled={busy} onClick={run}><Dna size={16} /> {busy ? "Fuzzing…" : "Run fuzzer"}</button>
        </div>
        <ErrorNote error={error} />
        {report && (
          <div className="cards four">
            <div className="stat"><div><span>Variants</span><strong>{report.totals.variants.toLocaleString()}</strong><small>{report.params.elapsed_seconds ?? "—"} s · {report.generations.length} generations</small></div></div>
            <div className="stat"><div><span>Detected</span><strong>{pct(report.totals.detection)}</strong><small>{report.totals.undetected} evaded the detector</small></div></div>
            <div className="stat"><div><span>Agent resisted</span><strong>{pct(report.totals.resistance)}</strong><small>{report.totals.hijacked} hijacked the agent</small></div></div>
            <div className={`stat ${report.totals.containment < 1 ? "alarm" : ""}`}><div><span>Contained</span><strong>{pct(report.totals.containment)}</strong><small>{report.totals.attack_success} successful attacks</small></div></div>
          </div>
        )}
      </section>

      {report && (
        <>
          <div className="grid">
            <section className="panel">
              <PanelHead eyebrow="DETECTION BY OPERATOR" title="Where the detector is weakest"
                action={
                  <select value={view} onChange={(e) => setView(e.target.value as typeof view)} aria-label="Operator view">
                    <option value="combined">Any stack containing it</option>
                    <option value="single">Operator alone</option>
                  </select>
                } />
              <Bars rows={operatorRows} metric="detection" />
              <p className="hint">Detector false-positive rate: <b>{pct(report.detector.false_positive_rate)}</b> on {report.detector.benign_texts} benign support messages and policy documents.</p>
            </section>
            <section className="panel">
              <PanelHead eyebrow="ROBUSTNESS CURVE" title="Detection vs. stacked mutations" />
              <Bars rows={Object.entries(report.by_depth).map(([d, b]) => [`depth ${d}`, b] as [string, Bucket])} metric="detection" />
              <p className="eyebrow" style={{ marginTop: 18 }}>EVOLUTION</p>
              <div className="metric-table">
                <div><span>Gen</span><span>Evasion · hijack</span><b>Best fitness</b></div>
                {report.generations.map((g) => (
                  <div key={g.generation}><span>{g.generation} ({g.variants})</span><span>{pct(g.evasion_rate)} · {pct(g.hijack_rate)}</span><b>{g.best_fitness}</b></div>
                ))}
              </div>
            </section>
          </div>

          <section className="panel">
            <PanelHead eyebrow="BY GOAL" title="Agent resistance and containment per attack goal" />
            <div className="gates">
              {Object.entries(report.by_goal).map(([goal, b]) => (
                <div key={goal} className={`gate ${b.containment < 1 ? "fail" : b.resistance < 0.95 ? "warn" : "pass"}`}>
                  <span>{goal.replaceAll("_", " ")}</span>
                  <b>{pct(b.containment)}</b>
                  <small>contained · resisted {pct(b.resistance)} · detected {pct(b.detection)}</small>
                </div>
              ))}
            </div>
          </section>

          <section className="panel">
            <PanelHead eyebrow="FINDINGS" title={report.successful_attacks.length ? "Successful attacks" : "Top evasions (contained by policy)"}
              action={
                <div className="row-gap">
                  <button onClick={() => exportCases("undetected")}><Download size={14} /> Undetected JSONL</button>
                  <button onClick={() => exportCases("hijacked")}><Download size={14} /> Hijacks JSONL</button>
                </div>
              } />
            {(report.successful_attacks.length ? report.successful_attacks : report.top_evasions).length === 0 ? (
              <div className="empty">No variant evaded the detector.</div>
            ) : (
              <div className="data-list compact">
                {(report.successful_attacks.length ? report.successful_attacks : report.top_evasions).map((e, i) => (
                  <div className="data-row case" key={i}>
                    <div><b>{e.goal} · {e.operators.join(" + ") || "no mutation"}</b><span><code>{e.payload_preview}</code></span></div>
                    <span className={`decision ${e.contained && e.privacy ? "good" : "danger"}`}>{e.contained && e.privacy ? "contained" : "breach"}</span>
                    <small>score {e.injection_score} · {e.source} · gen {e.generation} · {e.resisted ? "agent resisted" : `agent tried ${e.attempted.filter((a) => a !== "policy.search").join(", ") || "to comply"}`}</small>
                    <TraceLink traceId={e.trace_id} onOpen={onOpenTrace} />
                  </div>
                ))}
              </div>
            )}
            <p className="hint">Exported cases use the dataset schema, so they can be added to <code>datasets/</code> and become permanent regression tests.</p>
          </section>
        </>
      )}
    </>
  );
}
