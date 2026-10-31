"use client";

import { useEffect, useState } from "react";
import { Crosshair } from "lucide-react";
import { AgentVersion, sfGet, sfPost } from "../../lib/sf";
import { DecisionPill, ErrorNote, PageHeader, PanelHead, TraceLink } from "./ui";

type AttackResult = {
  case_id: string;
  attack_type: string;
  input_source: string;
  severity: string;
  agent_response: string | null;
  tool_calls_attempted: { action: string; decision: string; policy: string | null; executed: boolean }[];
  sensitive_data_exposed: boolean;
  agent_resisted: boolean;
  gateway_contained: boolean;
  passed: boolean;
  failures: string[];
  remediation: string | null;
  trace_id: string;
};

type Report = {
  evaluation_id: string;
  version_id: string;
  release_decision: string;
  summary: Record<string, { total: number; passed: number }>;
  total: number;
  passed: number;
  results: AttackResult[];
};

export function RedTeamLab({ onOpenTrace }: { onOpenTrace: (id: string) => void }) {
  const [versions, setVersions] = useState<AgentVersion[]>([]);
  const [versionId, setVersionId] = useState("support-agent-v2.0");
  const [report, setReport] = useState<Report | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<"all" | "failed" | "exposed">("all");

  useEffect(() => {
    sfGet<{ versions: AgentVersion[] }>("agent-versions")
      .then((b) => setVersions(b.versions.filter((v) => v.planner === "scripted")))
      .catch((e) => setError(e.message));
  }, []);

  async function run() {
    setBusy(true);
    setError(null);
    try {
      setReport(await sfPost<Report>("redteam/run", { version_id: versionId }));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const rows = (report?.results ?? []).filter((r) => filter === "all" || (filter === "failed" ? !r.passed : r.sensitive_data_exposed));
  const resisted = report ? report.results.filter((r) => r.agent_resisted).length : 0;
  const contained = report ? report.results.filter((r) => r.gateway_contained).length : 0;
  return (
    <>
      <PageHeader eyebrow="RED TEAM" title="Prompt-Injection Defense Lab"
        sub="Attacks from user messages, documents, PDFs, web pages, email, database fields and other agents. Runs in an isolated sandbox: nothing real is sent or exported." />
      <section className="panel">
        <div className="form inline">
          <select value={versionId} onChange={(e) => setVersionId(e.target.value)}>
            {versions.map((v) => <option key={v.version_id} value={v.version_id}>{v.version_id}</option>)}
          </select>
          <button className="primary" disabled={busy} onClick={run}><Crosshair size={16} /> {busy ? "Attacking…" : "Run attack suite"}</button>
        </div>
        <ErrorNote error={error} />
        {report && (
          <div className="cards three">
            <div className="stat"><div><span>Attacks</span><strong>{report.total}</strong><small>{report.passed} fully passed</small></div></div>
            <div className="stat"><div><span>Agent resisted</span><strong>{Math.round((resisted / report.total) * 100)}%</strong><small>never attempted the injected action</small></div></div>
            <div className="stat"><div><span>Gateway contained</span><strong>{Math.round((contained / report.total) * 100)}%</strong><small>forbidden actions never executed</small></div></div>
          </div>
        )}
      </section>

      {report && (
        <>
          <section className="panel">
            <PanelHead eyebrow="BY ATTACK TYPE" title="Where the agent breaks" />
            <div className="bars">
              {Object.entries(report.summary).sort().map(([type, b]) => (
                <div key={type} className="bar-row">
                  <span>{type}</span>
                  <span className="bar"><i style={{ width: `${(b.passed / b.total) * 100}%` }} /></span>
                  <small>{b.passed}/{b.total}</small>
                </div>
              ))}
            </div>
          </section>
          <section className="panel">
            <PanelHead eyebrow="RESULTS" title="Attack-by-attack evidence" badge={`${rows.length} SHOWN`}
              action={
                <select value={filter} onChange={(e) => setFilter(e.target.value as typeof filter)}>
                  <option value="all">All</option>
                  <option value="failed">Failed</option>
                  <option value="exposed">Data exposed</option>
                </select>
              } />
            <div className="data-list compact">
              {rows.map((r) => (
                <details className="data-row attack" key={r.case_id}>
                  <summary>
                    <div><b>{r.attack_type}</b><span>{r.case_id} · source: {r.input_source}</span></div>
                    <span className={`decision ${r.passed ? "good" : "danger"}`}>{r.passed ? "pass" : "fail"}</span>
                    <span>{r.agent_resisted ? "agent resisted" : "agent hijacked"} · {r.gateway_contained ? "contained" : "EXECUTED"}{r.sensitive_data_exposed ? " · data exposed" : ""}</span>
                  </summary>
                  <div className="span-body">
                    <p><b>Agent response:</b> {r.agent_response}</p>
                    <div className="chips">
                      {r.tool_calls_attempted.map((t, i) => (
                        <span key={i} className="chip static">{t.action} <DecisionPill decision={t.decision} /> {t.policy}</span>
                      ))}
                    </div>
                    {r.failures.length > 0 && <p className="danger-text">{r.failures.join("; ")}</p>}
                    {r.remediation && <p className="hint">Remediation: {r.remediation}</p>}
                    <TraceLink traceId={r.trace_id} onOpen={onOpenTrace} />
                  </div>
                </details>
              ))}
            </div>
          </section>
        </>
      )}
    </>
  );
}
