"use client";

import { useEffect, useState } from "react";
import { Workflow } from "lucide-react";
import { Observation, sfGet, sfPost } from "../../lib/sf";
import { DecisionPill, ErrorNote, PageHeader, PanelHead, StatusPill, TraceLink } from "./ui";

type SubAgent = { agent_id: string; permissions: string[]; role: string; delegated_scopes: string[] };
type Orchestration = { trace_id: string; status: string; output: string; route: string[]; steps: (Observation & { agent: string })[] };

const PRESETS = [
  "My order ORD-1077 arrived damaged, please refund ₹18,000",
  "Where is my order ORD-1042?",
  "I want to file a complaint, ORD-1042 is very late.",
  "What is your refund policy for defective items?",
];

export function MultiAgent({ onOpenTrace }: { onOpenTrace: (id: string) => void }) {
  const [agents, setAgents] = useState<Record<string, SubAgent>>({});
  const [message, setMessage] = useState(PRESETS[0]);
  const [overreach, setOverreach] = useState(true);
  const [result, setResult] = useState<Orchestration | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    sfGet<{ agents: Record<string, SubAgent> }>("orchestrations/agents").then((b) => setAgents(b.agents)).catch((e) => setError(e.message));
  }, []);

  async function run() {
    setError(null);
    try {
      setResult(await sfPost<Orchestration>("orchestrations/run", { message, user_id: "cus_128", simulate_overreach: overreach }));
    } catch (e) {
      setError((e as Error).message);
    }
  }

  return (
    <>
      <PageHeader eyebrow="LEAST PRIVILEGE" title="Multi-Agent Orchestration"
        sub="Triage routes work to specialists. Each has its own identity and only the tools its job needs; the responder can only use verified outputs." />
      <section className="panel">
        <PanelHead eyebrow="IDENTITIES" title="Who may do what" />
        <div className="policy-grid">
          {Object.entries(agents).map(([name, a]) => (
            <div key={name}>
              <b>{name}</b>
              <span>{a.role}</span>
              <span><code>{a.permissions.length ? a.permissions.join(", ") : "no tools"}</code></span>
            </div>
          ))}
        </div>
      </section>
      <section className="panel">
        <div className="form">
          <textarea rows={2} value={message} onChange={(e) => setMessage(e.target.value)} />
          <div className="chips">{PRESETS.map((p) => <button key={p} className="chip" onClick={() => setMessage(p)}>{p.slice(0, 40)}…</button>)}</div>
          <label className="check"><input type="checkbox" checked={overreach} onChange={(e) => setOverreach(e.target.checked)} /> Make Billing try to <b>issue</b> the refund itself (overreach)</label>
          <button className="primary" onClick={run}><Workflow size={16} /> Run orchestration (as cus_128)</button>
          <ErrorNote error={error} />
        </div>
      </section>
      {result && (
        <section className="panel">
          <PanelHead eyebrow="ROUTE" title={["triage", ...result.route, "responder"].join(" → ")} action={<StatusPill status={result.status} />} />
          <blockquote className="answer">{result.output}</blockquote>
          <div className="table">
            {result.steps.map((s, i) => (
              <div className="event" key={i}>
                <DecisionPill decision={s.decision} />
                <div className="event-main"><b>{s.agent} · {s.action}</b><span><code>{JSON.stringify(s.args)}</code></span></div>
                <div className="event-risk">{s.executed ? "Executed" : "Not executed"}</div>
                <div className="event-reason">{s.reason}</div>
              </div>
            ))}
          </div>
          <p className="hint">Trace: <TraceLink traceId={result.trace_id} onOpen={onOpenTrace} /></p>
        </section>
      )}
    </>
  );
}
