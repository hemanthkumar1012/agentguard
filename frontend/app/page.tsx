"use client";

import { useEffect, useState } from "react";

type Event = { event_id: string; agent_id: string; action: string; target: string; decision: string; risk_score: number; reason: string; created_at: string };
type Snapshot = {
  agents: { total: number; active: number; suspended: number; revoked: number };
  decisions: { total: number; allow: number; require_approval: number; block: number };
  risk: { average: number; maximum: number; high_risk_events: number };
  recent_events: Event[];
};

const fallback: Snapshot = { agents: { total: 0, active: 0, suspended: 0, revoked: 0 }, decisions: { total: 0, allow: 0, require_approval: 0, block: 0 }, risk: { average: 0, maximum: 0, high_risk_events: 0 }, recent_events: [] };

function decisionClass(decision: string) { return decision === "block" ? "danger" : decision === "require_approval" ? "warn" : "good"; }

export default function Home() {
  const [data, setData] = useState<Snapshot>(fallback);
  const [connected, setConnected] = useState(false);

  async function refresh() {
    try {
      const res = await fetch("/api/control-plane/snapshot", { cache: "no-store" });
      if (!res.ok) throw new Error();
      setData(await res.json());
      setConnected(true);
    } catch {
      setConnected(false);
    }
  }

  useEffect(() => { refresh(); const id = setInterval(refresh, 5000); return () => clearInterval(id); }, []);

  const riskWidth = `${Math.min(100, data.risk.average)}%`;
  return <main>
    <aside className="sidebar">
      <div className="brand"><span className="mark">AG</span><div><strong>AgentGuard</strong><small>CONTROL PLANE</small></div></div>
      <nav><a className="active">Overview</a><a>Agents</a><a>Security Events</a><a>Policies</a><a>Credentials</a><a>MCP Gateway</a><a>Attack Simulator</a></nav>
      <div className="side-status"><span className={connected ? "dot live" : "dot"}></span>{connected ? "API connected" : "API offline"}</div>
    </aside>

    <section className="content">
      <header><div><p className="eyebrow">RUNTIME SECURITY</p><h1>Security Overview</h1><p className="sub">Real-time authorization posture across your AI agent fleet.</p></div><button onClick={refresh}>↻ Refresh</button></header>

      <div className="cards">
        <Stat label="Registered agents" value={data.agents.total} meta={`${data.agents.active} active`} icon="◎" />
        <Stat label="Allowed actions" value={data.decisions.allow} meta={`${data.decisions.total} total decisions`} icon="✓" />
        <Stat label="Approval queue" value={data.decisions.require_approval} meta="Human review required" icon="!" warn />
        <Stat label="Blocked actions" value={data.decisions.block} meta={`${data.risk.high_risk_events} high-risk events`} icon="×" danger />
      </div>

      <div className="grid">
        <section className="panel risk"><div className="panel-head"><div><p className="eyebrow">RISK ENGINE</p><h2>Environment risk</h2></div><span className="badge">LIVE</span></div><div className="score"><strong>{Math.round(data.risk.average)}</strong><span>/100</span></div><div className="bar"><i style={{ width: riskWidth }} /></div><div className="risk-meta"><span>Average risk</span><span>Peak {Math.round(data.risk.maximum)}</span></div><p className="hint">Risk is calculated from action impact, data classification, target context and detected sensitive content.</p></section>
        <section className="panel"><div className="panel-head"><div><p className="eyebrow">AGENT FLEET</p><h2>Identity posture</h2></div></div><div className="fleet"><div><b>{data.agents.active}</b><span>Active</span></div><div><b>{data.agents.suspended}</b><span>Suspended</span></div><div><b>{data.agents.revoked}</b><span>Revoked</span></div></div><div className="mini-line"><span>Active fleet</span><b>{data.agents.total ? Math.round(data.agents.active / data.agents.total * 100) : 0}%</b></div></section>
      </div>

      <section className="panel events"><div className="panel-head"><div><p className="eyebrow">FORENSIC STREAM</p><h2>Recent security decisions</h2></div><span className="live-label"><i className="dot live"/> Streaming</span></div>
        {data.recent_events.length === 0 ? <div className="empty">No security events yet. Execute a tool request to populate the forensic stream.</div> : <div className="table">{data.recent_events.map(e => <div className="event" key={e.event_id}><span className={`decision ${decisionClass(e.decision)}`}>{e.decision.replace("_", " ")}</span><div className="event-main"><b>{e.action}</b><span>{e.agent_id} → {e.target}</span></div><div className="event-risk">Risk <b>{Math.round(e.risk_score)}</b></div><div className="event-reason">{e.reason}</div></div>)}</div>}
      </section>
    </section>
  </main>;
}

function Stat({ label, value, meta, icon, warn, danger }: { label: string; value: number; meta: string; icon: string; warn?: boolean; danger?: boolean }) { return <div className="stat"><div className={`stat-icon ${warn ? "warn" : danger ? "danger" : ""}`}>{icon}</div><div><span>{label}</span><strong>{value.toLocaleString()}</strong><small>{meta}</small></div></div>; }
