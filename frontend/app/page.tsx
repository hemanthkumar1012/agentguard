"use client";

import { useEffect, useState } from "react";

type Event = { event_id: string; agent_id: string; action: string; target: string; decision: string; risk_score: number; reason: string; created_at: string };
type Agent = { agent_id: string; name: string; owner: string; environment: string; permissions: string[]; status: string; created_at: string };
type Approval = { approval_id: string; event_id?: string; requested_by: string; status: string; request_fingerprint: string; expires_at: string; decided_by?: string; consumed_at?: string };
type Credential = { credential_id: string; agent_id: string; tool: string; scopes: string[]; expires_at: string; revoked: boolean };
type Snapshot = {
  agents: { total: number; active: number; suspended: number; revoked: number };
  decisions: { total: number; allow: number; require_approval: number; block: number };
  risk: { average: number; maximum: number; high_risk_events: number };
  recent_events: Event[];
};
type View = "overview" | "agents" | "events" | "approvals" | "policies" | "credentials" | "mcp" | "simulator";

const fallback: Snapshot = { agents: { total: 0, active: 0, suspended: 0, revoked: 0 }, decisions: { total: 0, allow: 0, require_approval: 0, block: 0 }, risk: { average: 0, maximum: 0, high_risk_events: 0 }, recent_events: [] };
const nav: { id: View; label: string }[] = [
  { id: "overview", label: "Overview" }, { id: "agents", label: "Agents" }, { id: "events", label: "Security Events" },
  { id: "approvals", label: "Approvals" }, { id: "policies", label: "Policies" }, { id: "credentials", label: "Credentials" },
  { id: "mcp", label: "MCP Gateway" }, { id: "simulator", label: "Attack Simulator" },
];

function decisionClass(decision: string) { return decision === "block" ? "danger" : decision === "require_approval" ? "warn" : "good"; }
function formatDate(value?: string) { return value ? new Date(value).toLocaleString() : "—"; }

export default function Home() {
  const [view, setView] = useState<View>("overview");
  const [data, setData] = useState<Snapshot>(fallback);
  const [connected, setConnected] = useState(false);
  const [items, setItems] = useState<Agent[] | Event[] | Approval[] | Credential[]>([]);

  async function loadSnapshot() {
    try { const res = await fetch("/api/control-plane/snapshot", { cache: "no-store" }); if (!res.ok) throw new Error(); setData(await res.json()); setConnected(true); }
    catch { setConnected(false); }
  }

  async function loadView(nextView: View) {
    setView(nextView);
    const resource = nextView === "agents" ? "agents" : nextView === "events" ? "events" : nextView === "approvals" ? "approvals" : nextView === "credentials" ? "credentials" : null;
    if (!resource) return;
    try { const res = await fetch(`/api/control-plane/${resource}`, { cache: "no-store" }); if (!res.ok) throw new Error(); const body = await res.json(); setItems(body.agents ?? body.events ?? body.approvals ?? body.credentials ?? []); }
    catch { setItems([]); }
  }

  useEffect(() => { loadSnapshot(); const id = setInterval(loadSnapshot, 5000); return () => clearInterval(id); }, []);

  return <main>
    <aside className="sidebar">
      <div className="brand"><span className="mark">AG</span><div><strong>AgentGuard</strong><small>CONTROL PLANE</small></div></div>
      <nav>{nav.map(item => <button key={item.id} className={view === item.id ? "active" : ""} onClick={() => loadView(item.id)}>{item.label}</button>)}</nav>
      <div className="side-status"><span className={connected ? "dot live" : "dot"}></span>{connected ? "API connected" : "API offline"}</div>
    </aside>
    <section className="content">
      {view === "overview" ? <Overview data={data} refresh={loadSnapshot} /> : <DetailView view={view} items={items} refresh={() => loadView(view)} />}
    </section>
  </main>;
}

function Overview({ data, refresh }: { data: Snapshot; refresh: () => void }) {
  const riskWidth = `${Math.min(100, data.risk.average)}%`;
  return <><header><div><p className="eyebrow">RUNTIME SECURITY</p><h1>Security Overview</h1><p className="sub">Real-time authorization posture across your AI agent fleet.</p></div><button onClick={refresh}>↻ Refresh</button></header>
    <div className="cards"><Stat label="Registered agents" value={data.agents.total} meta={`${data.agents.active} active`} icon="◎" /><Stat label="Allowed actions" value={data.decisions.allow} meta={`${data.decisions.total} total decisions`} icon="✓" /><Stat label="Approval queue" value={data.decisions.require_approval} meta="Human review required" icon="!" warn /><Stat label="Blocked actions" value={data.decisions.block} meta={`${data.risk.high_risk_events} high-risk events`} icon="×" danger /></div>
    <div className="grid"><section className="panel risk"><PanelHead eyebrow="RISK ENGINE" title="Environment risk" badge="LIVE" /><div className="score"><strong>{Math.round(data.risk.average)}</strong><span>/100</span></div><div className="bar"><i style={{ width: riskWidth }} /></div><div className="risk-meta"><span>Average risk</span><span>Peak {Math.round(data.risk.maximum)}</span></div><p className="hint">Risk is calculated from action impact, data classification, target context and detected sensitive content.</p></section><section className="panel"><PanelHead eyebrow="AGENT FLEET" title="Identity posture" /><div className="fleet"><div><b>{data.agents.active}</b><span>Active</span></div><div><b>{data.agents.suspended}</b><span>Suspended</span></div><div><b>{data.agents.revoked}</b><span>Revoked</span></div></div><div className="mini-line"><span>Active fleet</span><b>{data.agents.total ? Math.round(data.agents.active / data.agents.total * 100) : 0}%</b></div></section></div>
    <EventTable events={data.recent_events} />
  </>;
}

function DetailView({ view, items, refresh }: { view: View; items: Agent[] | Event[] | Approval[] | Credential[]; refresh: () => void }) {
  const title = nav.find(item => item.id === view)?.label ?? "Control Plane";
  return <><header><div><p className="eyebrow">CONTROL PLANE</p><h1>{title}</h1><p className="sub">Inspect runtime state and security controls without exposing server credentials.</p></div><button onClick={refresh}>↻ Refresh</button></header>
    {view === "agents" && <AgentTable agents={items as Agent[]} />}
    {view === "events" && <EventTable events={items as Event[]} />}
    {view === "approvals" && <ApprovalTable approvals={items as Approval[]} />}
    {view === "credentials" && <CredentialTable credentials={items as Credential[]} />}
    {view === "policies" && <PolicyView />}
    {view === "mcp" && <McpView />}
    {view === "simulator" && <SimulatorView />}
  </>;
}

function PanelHead({ eyebrow, title, badge }: { eyebrow: string; title: string; badge?: string }) { return <div className="panel-head"><div><p className="eyebrow">{eyebrow}</p><h2>{title}</h2></div>{badge && <span className="badge">{badge}</span>}</div>; }
function Stat({ label, value, meta, icon, warn, danger }: { label: string; value: number; meta: string; icon: string; warn?: boolean; danger?: boolean }) { return <div className="stat"><div className={`stat-icon ${warn ? "warn" : danger ? "danger" : ""}`}>{icon}</div><div><span>{label}</span><strong>{value.toLocaleString()}</strong><small>{meta}</small></div></div>; }
function EventTable({ events }: { events: Event[] }) { return <section className="panel events"><PanelHead eyebrow="FORENSIC STREAM" title="Security decisions" badge={`${events.length} EVENTS`} />{events.length === 0 ? <div className="empty">No security events found.</div> : <div className="table">{events.map(e => <div className="event" key={e.event_id}><span className={`decision ${decisionClass(e.decision)}`}>{e.decision.replace("_", " ")}</span><div className="event-main"><b>{e.action}</b><span>{e.agent_id} → {e.target}</span></div><div className="event-risk">Risk <b>{Math.round(e.risk_score)}</b></div><div className="event-reason">{e.reason}<br />{formatDate(e.created_at)}</div></div>)}</div>}</section>; }
function AgentTable({ agents }: { agents: Agent[] }) { return <section className="panel"><PanelHead eyebrow="IDENTITY" title="Registered agents" />{agents.length === 0 ? <div className="empty">No agents found.</div> : <div className="data-list">{agents.map(a => <div className="data-row" key={a.agent_id}><div><b>{a.name}</b><span>{a.agent_id} · {a.owner}</span></div><span className={`status ${a.status}`}>{a.status}</span><span>{a.permissions.join(", ") || "No permissions"}</span><small>{a.environment}</small></div>)}</div>}</section>; }
function ApprovalTable({ approvals }: { approvals: Approval[] }) { return <section className="panel"><PanelHead eyebrow="HUMAN GATE" title="Approval queue" />{approvals.length === 0 ? <div className="empty">No approval requests found.</div> : <div className="data-list">{approvals.map(a => <div className="data-row" key={a.approval_id}><div><b>{a.approval_id}</b><span>Requested by {a.requested_by}</span></div><span className={`status ${a.status}`}>{a.status}</span><small>Expires {formatDate(a.expires_at)}</small></div>)}</div>}</section>; }
function CredentialTable({ credentials }: { credentials: Credential[] }) { return <section className="panel"><PanelHead eyebrow="CREDENTIAL BROKER" title="Scoped credentials" />{credentials.length === 0 ? <div className="empty">No credentials found. Tokens are never returned after issuance.</div> : <div className="data-list">{credentials.map(c => <div className="data-row" key={c.credential_id}><div><b>{c.credential_id}</b><span>{c.agent_id} · {c.tool}</span></div><span>{c.scopes.join(", ")}</span><small>{c.revoked ? "Revoked" : `Expires ${formatDate(c.expires_at)}`}</small></div>)}</div>}</section>; }
function PolicyView() { return <section className="panel"><PanelHead eyebrow="POLICY ENGINE" title="Deterministic enforcement rules" /><div className="policy-grid">{[["Identity", "Unknown, suspended, and revoked agents are blocked."], ["Least privilege", "The requested action must exist in the agent permission set."], ["Credentials", "Tool calls require a matching, short-lived scoped credential."], ["Risk", "Sensitive data, high-impact actions, external targets, and HTTP targets increase risk."], ["Human approval", "Sensitive requests at risk 60+ or any request at risk 70+ require approval."], ["Hard block", "High-impact actions at risk 80+ are blocked without an approval bypass."]].map(([name, text]) => <div key={name}><b>{name}</b><span>{text}</span></div>)}</div></section>; }
function McpView() { return <section className="panel"><PanelHead eyebrow="MCP BOUNDARY" title="Authorize before execute" badge="ENFORCED" /><p className="hint">MCP calls enter the same gateway as direct tool requests. Identity, permission, scoped credentials, data inspection, risk, approval, and audit checks all run before a registered handler executes.</p><div className="callout"><b>Runtime status</b><span>HTTP MCP endpoint is available at <code>/api/v1/mcp/call</code>.</span></div></section>; }
function SimulatorView() { return <section className="panel"><PanelHead eyebrow="RED TEAM" title="Synthetic attack scenarios" badge="SAFE" /><p className="hint">The simulator exercises authorization only. It does not call external tools, send messages, access customer records, or exfiltrate data.</p><div className="policy-grid"><div><b>Prompt injection → PII export</b><span>Expected result: block</span></div><div><b>Privilege escalation</b><span>Expected result: block</span></div><div><b>External secret exfiltration</b><span>Expected result: block</span></div></div></section>; }
