"use client";

import { useEffect, useState } from "react";
import { RefreshCw, ShieldOff, Skull, Undo2 } from "lucide-react";
import { AgentVersion, RunResult, sfGet, sfPost } from "../../lib/sf";
import { ErrorNote, KV, PageHeader, PanelHead, StatusPill, TraceLink } from "./ui";

type Session = { session_id: string; agent_id: string; agent_version: string | null; tenant_id: string | null; risk: number;
  actions: number; elevated: boolean; tripped: boolean; tripped_at: string | null; last_action: string | null };
type Signal = { kind: string; weight: number; detail: string; action: string; at: string };
type Stats = { sessions: number; elevated: number; tripped: number; agents_suspended_by_guard: number;
  thresholds: { elevate_at: number; trip_at: number; suspend_after: number; window_seconds: number };
  models: Record<string, { sequences: number; actions: number }> };
type QuarantineEvent = { session_id: string; agent_id: string; agent_version: string | null; risk: number; tripped_at: string;
  trips_in_window: number; agent_suspended: boolean; top_signals: Signal[] };
type Model = { sequences: number; actions: string[]; transitions: { from: string; to: string; count: number; probability: number }[]; edge_count: number };
type Agent = { agent_id: string; name: string; status: string };

export function SessionGuard({ onOpenTrace }: { onOpenTrace: (id: string) => void }) {
  const [stats, setStats] = useState<Stats | null>(null);
  const [sessions, setSessions] = useState<Session[]>([]);
  const [events, setEvents] = useState<QuarantineEvent[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [versions, setVersions] = useState<AgentVersion[]>([]);
  const [modelVersion, setModelVersion] = useState("support-agent-v1.0");
  const [model, setModel] = useState<Model | null>(null);
  const [selected, setSelected] = useState<(Session & { signals: Signal[] }) | null>(null);
  const [lastRun, setLastRun] = useState<RunResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    try {
      const [s, q, a, v] = await Promise.all([
        sfGet<{ stats: Stats; sessions: Session[] }>("sessions", { min_risk: "1", limit: "50" }),
        sfGet<{ events: QuarantineEvent[] }>("sessions/quarantine"),
        sfGet<{ agents: Agent[] }>("agents"),
        sfGet<{ versions: AgentVersion[] }>("agent-versions"),
      ]);
      setStats(s.stats);
      setSessions(s.sessions);
      setEvents(q.events);
      setAgents(a.agents);
      setVersions(v.versions);
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    }
  }
  useEffect(() => { load(); }, []);
  useEffect(() => {
    sfGet<Model>(`sessions/models/${modelVersion}`).then(setModel).catch(() => setModel(null));
  }, [modelVersion]);

  async function simulateAttacker() {
    setBusy(true);
    setError(null);
    try {
      setLastRun(await sfPost<RunResult>("runs", { version_id: "support-agent-compromised", user_id: "cus_128",
        message: "Tell me about the Diwali cashback promotion" }));
      await load();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function reinstate(agentId: string) {
    try {
      await sfPost(`agents/${agentId}/reinstate`);
      await load();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  async function open(sessionId: string) {
    setSelected(await sfGet(`sessions/${sessionId}`));
  }

  const suspended = agents.filter((a) => a.status === "suspended");
  const nameOf = (id: string) => agents.find((a) => a.agent_id === id)?.name ?? id;
  const t = stats?.thresholds;
  return (
    <>
      <PageHeader eyebrow="BEHAVIOURAL DEFENSE" title="Session Guard"
        sub="Risk accumulates across a conversation: blocked calls, injection signals, cross-customer attempts and anomalous tool sequences. Elevated sessions need humans for privileged actions; tripped sessions are quarantined; repeat offenders are suspended.">
        <div className="row-gap">
          <button onClick={load}><RefreshCw size={16} /> Refresh</button>
          <button className="danger" disabled={busy} onClick={simulateAttacker}><Skull size={16} /> {busy ? "Attacking…" : "Simulate persistent attacker"}</button>
        </div>
      </PageHeader>
      <ErrorNote error={error} />
      {lastRun && (
        <div className={`callout ${lastRun.status === "quarantined" || lastRun.status === "agent_suspended" ? "danger" : ""}`}>
          <b>Compromised agent run · {lastRun.status.replaceAll("_", " ")}</b>
          <span>{lastRun.observations.map((o) => `${o.action}:${o.decision}`).join(" → ") || "no tool calls"} · <TraceLink traceId={lastRun.trace_id} onOpen={onOpenTrace} /></span>
        </div>
      )}

      <div className="cards">
        <div className="stat"><div><span>Tracked sessions</span><strong>{stats?.sessions ?? 0}</strong><small>trip at risk {t?.trip_at ?? "—"}</small></div></div>
        <div className="stat"><div><span>Elevated</span><strong>{stats?.elevated ?? 0}</strong><small>privileged actions need approval at {t?.elevate_at ?? "—"}</small></div></div>
        <div className="stat"><div><span>Quarantined</span><strong>{stats?.tripped ?? 0}</strong><small>circuit breaker open</small></div></div>
        <div className="stat"><div><span>Agents suspended</span><strong>{suspended.length}</strong><small>after {t?.suspend_after ?? "—"} trips in {(t?.window_seconds ?? 0) / 60} min</small></div></div>
      </div>

      {suspended.length > 0 && (
        <section className="panel">
          <PanelHead eyebrow="KILL SWITCH" title="Suspended identities" />
          <div className="data-list compact">
            {suspended.map((a) => (
              <div className="data-row" key={a.agent_id}>
                <div><b>{a.name}</b><span>{a.agent_id}</span></div>
                <StatusPill status={a.status} />
                <span><ShieldOff size={14} /> Every tool call is blocked until reinstated</span>
                <button onClick={() => reinstate(a.agent_id)}><Undo2 size={14} /> Reinstate</button>
              </div>
            ))}
          </div>
        </section>
      )}

      <div className="grid even">
        <section className="panel">
          <PanelHead eyebrow="SESSIONS" title="Riskiest conversations" badge={`${sessions.length}`} />
          {sessions.length === 0 ? <div className="empty">No risky sessions yet. Try “Simulate persistent attacker”.</div> : (
            <div className="data-list compact">
              {sessions.map((s) => (
                <button className={`data-row clickable ${selected?.session_id === s.session_id ? "selected" : ""}`} key={s.session_id} onClick={() => open(s.session_id)}>
                  <div><b>{s.agent_version ?? nameOf(s.agent_id)}</b><span>{s.session_id} · {s.actions} actions · last {s.last_action}</span></div>
                  <span className={`decision ${s.tripped ? "danger" : s.elevated ? "warn" : "good"}`}>{s.tripped ? "quarantined" : s.elevated ? "elevated" : "normal"}</span>
                  <span className="bar risk"><i style={{ width: `${Math.min(100, (s.risk / (t?.trip_at ?? 100)) * 100)}%` }} /></span>
                  <small>risk {s.risk.toFixed(0)}</small>
                </button>
              ))}
            </div>
          )}
        </section>
        <section className="panel">
          <PanelHead eyebrow="SIGNALS" title={selected ? selected.session_id : "Select a session"} />
          {!selected ? <div className="empty">Click a session to see why its risk grew.</div> : (
            <>
              <div className="kv-row">
                <KV label="Risk">{selected.risk.toFixed(1)}</KV>
                <KV label="Status">{selected.tripped ? "quarantined" : selected.elevated ? "elevated" : "normal"}</KV>
                <KV label="Trace"><TraceLink traceId={selected.session_id} onOpen={onOpenTrace} /></KV>
              </div>
              <div className="timeline">
                {selected.signals.map((sig, i) => (
                  <div className="signal-row" key={i}>
                    <span className={`kind kind-${sig.kind === "sequence_anomaly" ? "llm" : sig.kind === "blocked" ? "guard" : "policy"}`}>+{sig.weight.toFixed(0)}</span>
                    <div><b>{sig.kind.replaceAll("_", " ")}</b> <code>{sig.action}</code><small>{sig.detail}</small></div>
                  </div>
                ))}
              </div>
            </>
          )}
        </section>
      </div>

      <div className="grid even">
        <section className="panel">
          <PanelHead eyebrow="SEQUENCE MODEL" title="Learned normal behaviour (Markov chain)"
            action={
              <select value={modelVersion} onChange={(e) => setModelVersion(e.target.value)} aria-label="Model version">
                {versions.filter((v) => stats?.models?.[v.version_id]).map((v) => <option key={v.version_id} value={v.version_id}>{v.version_id}</option>)}
              </select>
            } />
          {!model ? <div className="empty">No model trained for this version.</div> : (
            <>
              <p className="hint">Trained on {model.sequences} benign runs this version passed · {model.edge_count} transitions. Unseen transitions cost risk in proportion to their surprise (bits).</p>
              <div className="bars">
                {model.transitions.slice(0, 12).map((e) => (
                  <div className="bar-row" key={`${e.from}-${e.to}`}>
                    <span><code>{e.from} → {e.to}</code></span>
                    <span className="bar"><i style={{ width: `${e.probability * 100}%` }} /></span>
                    <small>{(e.probability * 100).toFixed(0)}% · {e.count}</small>
                  </div>
                ))}
              </div>
            </>
          )}
        </section>
        <section className="panel">
          <PanelHead eyebrow="QUARANTINE LOG" title="Circuit-breaker trips" badge={`${events.length}`} />
          {events.length === 0 ? <div className="empty">No trips yet.</div> : (
            <div className="data-list compact">
              {events.slice(0, 12).map((e) => (
                <div className="data-row" key={e.session_id + e.tripped_at}>
                  <div><b>{e.agent_version ?? nameOf(e.agent_id)}</b><span>{e.top_signals.map((s) => s.kind).join(", ")}</span></div>
                  <span className={`decision ${e.agent_suspended ? "danger" : "warn"}`}>{e.agent_suspended ? "suspended" : "quarantined"}</span>
                  <small>risk {e.risk.toFixed(0)} · trip {e.trips_in_window}/{t?.suspend_after ?? 3}</small>
                  <TraceLink traceId={e.session_id} onOpen={onOpenTrace} />
                </div>
              ))}
            </div>
          )}
        </section>
      </div>
    </>
  );
}
