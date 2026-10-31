"use client";

import { useEffect, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  LayoutDashboard, Users, Activity, CheckCircle2, ShieldAlert, Key, Network, Target, ShieldCheck,
  AlertTriangle, XCircle, RefreshCw, MessageSquare, ListTree, FlaskConical, Workflow, Coins, Timer, Gauge,
} from "lucide-react";
import { RiskChart, RiskPoint } from "../components/RiskChart";
import { TerminalStream } from "../components/TerminalStream";
import { CommandMenu } from "../components/CommandMenu";
import { Playground } from "../components/sentinel/Playground";
import { TraceExplorer } from "../components/sentinel/TraceExplorer";
import { ApprovalInbox } from "../components/sentinel/ApprovalInbox";
import { Evaluations } from "../components/sentinel/Evaluations";
import { RedTeamLab } from "../components/sentinel/RedTeamLab";
import { MultiAgent } from "../components/sentinel/MultiAgent";
import { PolicyStudio } from "../components/sentinel/PolicyStudio";
import { SessionGuard } from "../components/sentinel/SessionGuard";
import { DecisionPill } from "../components/sentinel/ui";
import { inr, sfGet } from "../lib/sf";

type Event = { event_id: string; agent_id: string; action: string; target: string; decision: string; risk_score: number; reason: string; created_at: string; policy_id?: string | null };
type Agent = { agent_id: string; name: string; owner: string; environment: string; permissions: string[]; status: string; created_at: string };
type Credential = { credential_id: string; agent_id: string; tool: string; scopes: string[]; expires_at: string; revoked: boolean };
type Snapshot = {
  agents: { total: number; active: number; suspended: number; revoked: number };
  decisions: { total: number; allow: number; require_approval: number; block: number; allow_with_redaction?: number; rate_limit?: number; escalate_to_human?: number };
  risk: { average: number; maximum: number; high_risk_events: number };
  recent_events: Event[];
};
type Stats = { runs: number; avg_latency_ms: number; p95_latency_ms: number; total_cost_inr: number; total_tokens: number; blocked_actions: number; tool_errors: number; by_status: Record<string, number>; risk_trend: RiskPoint[] };
export type View = "overview" | "sessions" | "playground" | "traces" | "approvals" | "evaluations" | "redteam" | "multiagent" | "policies" | "agents" | "events" | "credentials" | "mcp";

const fallback: Snapshot = { agents: { total: 0, active: 0, suspended: 0, revoked: 0 }, decisions: { total: 0, allow: 0, require_approval: 0, block: 0 }, risk: { average: 0, maximum: 0, high_risk_events: 0 }, recent_events: [] };
export const nav: { id: View; label: string; icon: React.ReactNode; group: string }[] = [
  { id: "overview", label: "Overview", icon: <LayoutDashboard size={18} />, group: "Monitor" },
  { id: "traces", label: "Trace Explorer", icon: <ListTree size={18} />, group: "Monitor" },
  { id: "approvals", label: "Approval Inbox", icon: <ShieldAlert size={18} />, group: "Monitor" },
  { id: "sessions", label: "Session Guard", icon: <Gauge size={18} />, group: "Monitor" },
  { id: "playground", label: "Agent Playground", icon: <MessageSquare size={18} />, group: "Agents" },
  { id: "multiagent", label: "Multi-Agent", icon: <Workflow size={18} />, group: "Agents" },
  { id: "evaluations", label: "Evaluations", icon: <FlaskConical size={18} />, group: "Release" },
  { id: "redteam", label: "Red-Team Lab", icon: <Target size={18} />, group: "Release" },
  { id: "policies", label: "Policy Studio", icon: <ShieldCheck size={18} />, group: "Govern" },
  { id: "agents", label: "Identities", icon: <Users size={18} />, group: "Govern" },
  { id: "events", label: "Audit Log", icon: <Activity size={18} />, group: "Govern" },
  { id: "credentials", label: "Credentials", icon: <Key size={18} />, group: "Govern" },
  { id: "mcp", label: "MCP Gateway", icon: <Network size={18} />, group: "Govern" },
];

function formatDate(value?: string) { return value ? new Date(value).toLocaleString() : "—"; }

export default function Home() {
  const [view, setView] = useState<View>("overview");
  const [data, setData] = useState<Snapshot>(fallback);
  const [stats, setStats] = useState<Stats | null>(null);
  const [connected, setConnected] = useState(false);
  const [items, setItems] = useState<Agent[] | Event[] | Credential[]>([]);
  const [traceId, setTraceId] = useState<string | null>(null);

  async function loadSnapshot() {
    try {
      const res = await fetch("/api/control-plane/snapshot", { cache: "no-store" });
      if (!res.ok) throw new Error();
      setData(await res.json());
      setConnected(true);
      setStats(await sfGet<Stats>("observability/stats").catch(() => null));
    } catch { setConnected(false); }
  }

  async function loadView(nextView: View) {
    setView(nextView);
    const resource = nextView === "agents" ? "agents" : nextView === "events" ? "events" : nextView === "credentials" ? "credentials" : null;
    if (!resource) return;
    try {
      const res = await fetch(`/api/control-plane/${resource}`, { cache: "no-store" });
      if (!res.ok) throw new Error();
      const body = await res.json();
      setItems(body.agents ?? body.events ?? body.credentials ?? []);
    } catch { setItems([]); }
  }

  const openTrace = (id: string) => { setTraceId(id); setView("traces"); };

  useEffect(() => { loadSnapshot(); const id = setInterval(loadSnapshot, 5000); return () => clearInterval(id); }, []);

  let lastGroup = "";
  return (
    <main>
      <CommandMenu setView={loadView} />
      <aside className="sidebar">
        <div className="brand"><span className="mark">SF</span><div><strong>SentinelForge</strong><small>AGENT CONTROL PLANE</small></div></div>
        <nav>
          {nav.map(item => {
            const header = item.group !== lastGroup ? <p className="nav-group" key={`g-${item.group}`}>{item.group}</p> : null;
            lastGroup = item.group;
            return [header,
              <button key={item.id} className={view === item.id ? "active" : ""} onClick={() => loadView(item.id)} style={{ position: "relative" }}>
                {view === item.id && (
                  <motion.div layoutId="activeTab"
                    style={{ position: "absolute", left: 0, top: 0, bottom: 0, width: "3px", backgroundColor: "#3b82f6", borderRadius: "0 4px 4px 0" }}
                    transition={{ type: "spring", stiffness: 300, damping: 30 }} />
                )}
                <span style={{ marginLeft: view === item.id ? "8px" : "0", transition: "margin 0.2s ease", display: "flex", alignItems: "center", gap: "12px" }}>
                  {item.icon} {item.label}
                </span>
              </button>];
          })}
        </nav>
        <div className="side-status">
          <span className={connected ? "dot live" : "dot"}></span>
          {connected ? "API connected" : "API offline"}
          <span style={{ marginLeft: "auto", fontSize: "10px", color: "#52525b" }}>CMD+K</span>
        </div>
      </aside>

      <section className="content">
        <AnimatePresence mode="wait">
          <motion.div key={view} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }} transition={{ duration: 0.2 }}>
            {view === "overview" && <Overview data={data} stats={stats} refresh={loadSnapshot} openTrace={openTrace} />}
            {view === "playground" && <Playground onOpenTrace={openTrace} onOpenInbox={() => setView("approvals")} />}
            {view === "traces" && <TraceExplorer initialTraceId={traceId} />}
            {view === "approvals" && <ApprovalInbox onOpenTrace={openTrace} />}
            {view === "evaluations" && <Evaluations onOpenTrace={openTrace} />}
            {view === "redteam" && <RedTeamLab onOpenTrace={openTrace} />}
            {view === "multiagent" && <MultiAgent onOpenTrace={openTrace} />}
            {view === "policies" && <PolicyStudio />}
            {view === "sessions" && <SessionGuard onOpenTrace={openTrace} />}
            {["agents", "events", "credentials", "mcp"].includes(view) && <DetailView view={view} items={items} refresh={() => loadView(view)} />}
          </motion.div>
        </AnimatePresence>
      </section>
    </main>
  );
}

function Overview({ data, stats, refresh, openTrace }: { data: Snapshot; stats: Stats | null; refresh: () => void; openTrace: (id: string) => void }) {
  const held = data.decisions.require_approval + (data.decisions.escalate_to_human ?? 0);
  return (
    <>
      <header>
        <div>
          <p className="eyebrow">SENTINELFORGE · FINTECH SUPPORT OPERATIONS</p>
          <h1>Security Overview</h1>
          <p className="sub">Every agent tool call is authorized, traced and audited before it can touch money or customer data.</p>
        </div>
        <motion.button whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }} onClick={refresh}><RefreshCw size={16} /> Refresh</motion.button>
      </header>

      <div className="cards">
        <Stat label="Allowed actions" value={data.decisions.allow + (data.decisions.allow_with_redaction ?? 0)} meta={`${data.decisions.allow_with_redaction ?? 0} with redaction`} icon={<CheckCircle2 size={24} />} />
        <Stat label="Held for humans" value={held} meta={`${data.decisions.escalate_to_human ?? 0} escalations`} icon={<AlertTriangle size={24} />} warn />
        <Stat label="Blocked actions" value={data.decisions.block + (data.decisions.rate_limit ?? 0)} meta={`${data.decisions.rate_limit ?? 0} rate-limited`} icon={<XCircle size={24} />} danger />
        <Stat label="Agent runs" value={stats?.runs ?? 0} meta={`${stats?.blocked_actions ?? 0} unsafe attempts stopped`} icon={<Users size={24} />} />
      </div>
      <div className="cards">
        <Stat label="p95 run latency" value={Math.round(stats?.p95_latency_ms ?? 0)} meta={`avg ${Math.round(stats?.avg_latency_ms ?? 0)} ms · excl. approval waits`} icon={<Timer size={24} />} suffix=" ms" />
        <Stat label="LLM spend (est.)" value={stats?.total_cost_inr ?? 0} meta={`${(stats?.total_tokens ?? 0).toLocaleString()} tokens`} icon={<Coins size={24} />} money />
        <Stat label="Tool errors" value={stats?.tool_errors ?? 0} meta="failed tool executions" icon={<Activity size={24} />} />
        <Stat label="Awaiting approval" value={stats?.by_status?.awaiting_approval ?? 0} meta="paused agent runs" icon={<ShieldAlert size={24} />} warn />
      </div>

      <div className="grid">
        <section className="panel risk">
          <div className="panel-head"><div><p className="eyebrow">RISK ENGINE</p><h2>Max risk per agent run</h2></div><span className="badge">LIVE</span></div>
          <div className="score"><strong>{Math.round(data.risk.average)}</strong><span>/100 avg decision risk</span></div>
          <RiskChart points={stats?.risk_trend ?? []} />
          <div className="risk-meta"><span>{data.risk.high_risk_events} high-risk decisions</span><span>Peak {Math.round(data.risk.maximum)}</span></div>
        </section>
        <section className="panel">
          <div className="panel-head"><div><p className="eyebrow">GATEWAY</p><h2>Live decision stream</h2></div></div>
          <TerminalStream events={data.recent_events} />
          {stats && stats.risk_trend.length > 0 && (
            <p className="hint">Latest run: <button className="link-button" onClick={() => openTrace(stats.risk_trend[stats.risk_trend.length - 1].trace_id)}>{stats.risk_trend[stats.risk_trend.length - 1].trace_id}</button></p>
          )}
        </section>
      </div>
      <EventTable events={data.recent_events} />
    </>
  );
}

function DetailView({ view, items, refresh }: { view: View; items: Agent[] | Event[] | Credential[]; refresh: () => void }) {
  const title = nav.find(item => item.id === view)?.label ?? "Control Plane";
  return (
    <>
      <header>
        <div>
          <p className="eyebrow">CONTROL PLANE</p>
          <h1>{title}</h1>
          <p className="sub">Inspect runtime state and security controls without exposing server credentials.</p>
        </div>
        <motion.button whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }} onClick={refresh}><RefreshCw size={16} /> Refresh</motion.button>
      </header>
      {view === "agents" && <AgentTable agents={items as Agent[]} />}
      {view === "events" && <EventTable events={items as Event[]} />}
      {view === "credentials" && <CredentialTable credentials={items as Credential[]} />}
      {view === "mcp" && <McpView />}
    </>
  );
}

function PanelHead({ eyebrow, title, badge }: { eyebrow: string; title: string; badge?: string }) {
  return <div className="panel-head"><div><p className="eyebrow">{eyebrow}</p><h2>{title}</h2></div>{badge && <span className="badge">{badge}</span>}</div>;
}
function Stat({ label, value, meta, icon, warn, danger, money, suffix }: { label: string; value: number; meta: string; icon: React.ReactNode; warn?: boolean; danger?: boolean; money?: boolean; suffix?: string }) {
  return (
    <motion.div className="stat" whileHover={{ y: -4, transition: { duration: 0.2 } }}>
      <div className={`stat-icon ${warn ? "warn" : danger ? "danger" : ""}`}>{icon}</div>
      <div><span>{label}</span><strong>{money ? inr(value) : `${value.toLocaleString()}${suffix ?? ""}`}</strong><small>{meta}</small></div>
    </motion.div>
  );
}

function EventTable({ events }: { events: Event[] }) {
  return (
    <section className="panel events">
      <PanelHead eyebrow="FORENSIC STREAM" title="Security decisions" badge={`${events.length} EVENTS`} />
      {events.length === 0 ? <div className="empty">No security events found.</div> : (
        <div className="table">
          {events.map(e => (
            <div className="event" key={e.event_id}>
              <DecisionPill decision={e.decision} />
              <div className="event-main"><b>{e.action}</b><span>{e.agent_id} → {e.target}</span></div>
              <div className="event-risk">Risk <b>{Math.round(e.risk_score)}</b></div>
              <div className="event-reason">{e.policy_id && <><code>{e.policy_id}</code> · </>}{e.reason}<br />{formatDate(e.created_at)}</div>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
function AgentTable({ agents }: { agents: Agent[] }) { return <section className="panel"><PanelHead eyebrow="IDENTITY" title="Registered agent identities" />{agents.length === 0 ? <div className="empty">No agents found.</div> : <div className="data-list">{agents.map(a => <div className="data-row" key={a.agent_id}><div><b>{a.name}</b><span>{a.agent_id} · {a.owner}</span></div><span className={`status ${a.status}`}>{a.status}</span><span>{a.permissions.join(", ") || "No permissions"}</span><small>{a.environment}</small></div>)}</div>}</section>; }
function CredentialTable({ credentials }: { credentials: Credential[] }) { return <section className="panel"><PanelHead eyebrow="CREDENTIAL BROKER" title="Scoped credentials" />{credentials.length === 0 ? <div className="empty">No credentials found. Tokens are never returned after issuance.</div> : <div className="data-list">{credentials.map(c => <div className="data-row" key={c.credential_id}><div><b>{c.credential_id}</b><span>{c.agent_id} · {c.tool}</span></div><span>{c.scopes.join(", ")}</span><small>{c.revoked ? "Revoked" : `Expires ${formatDate(c.expires_at)}`}</small></div>)}</div>}</section>; }
function McpView() { return <section className="panel"><PanelHead eyebrow="MCP BOUNDARY" title="Authorize before execute" badge="ENFORCED" /><p className="hint">MCP calls enter the same gateway as direct tool requests. Identity, permission, scoped credentials, data inspection, prompt-injection scoring, declarative policy, approval, and audit checks all run before a registered handler executes. Redacted payloads are what the handler receives.</p><div className="callout"><b>Runtime status</b><span>HTTP MCP endpoint is available at <code>/api/v1/mcp/call</code>.</span></div></section>; }
