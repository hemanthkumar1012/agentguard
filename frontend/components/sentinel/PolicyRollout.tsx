"use client";

import { useEffect, useState } from "react";
import { Eye, GitBranch, Radar, Rocket, Undo2 } from "lucide-react";
import { sfGet, sfPost } from "../../lib/sf";
import { DecisionPill, ErrorNote, KV, PanelHead } from "./ui";

type Rule = { id: string; when: Record<string, unknown>; decision: string; [key: string]: unknown };
type Pack = { version: string; policies: Rule[] };
type Flip = { action: string; tenant_id: string | null; amount: number | null; before: string; after: string; before_policy: string | null; after_policy: string | null; source: string };
type Replay = { records: number; agreement_rate: number | null; tightened: number; relaxed: number; transitions: Record<string, Record<string, number>>;
  relaxation_examples: Flip[]; tightening_examples: Flip[]; dead_rules: string[] };
type GateReport = { live_decision: string; candidate_decision: string; release_regressed: boolean; live_passed: number; candidate_passed: number; cases: number;
  gates: { metric: string; live: number | null; candidate: number | null; regressed: boolean; critical: boolean }[];
  newly_failing_cases: { case_id: string; failures: string[] }[]; newly_passing_cases: string[] };
type Impact = {
  verdict: "unsafe" | "review" | "tightening" | "no_change"; summary: string; candidate_version: string; agent_versions: string[];
  regressed_versions: string[];
  diff: { added: string[]; removed: string[]; changed: { id: string; fields: string[]; before: Record<string, unknown>; after: Record<string, unknown> }[] };
  live_history?: Replay; evaluation_corpus?: Replay;
  release_gates?: Record<string, GateReport>;
};
type Shadow = { active: boolean; version: string | null; decisions: number; agreement_rate: number | null; looser: number; tighter: number;
  disagreements: (Flip & { live: string; shadow: string; direction: string })[] };
type Canary = { version: string; tenants: string[]; percent: number; strictness_shift: number | null; anomalous: boolean;
  canary: { decisions: number; hold_rate: number | null; block_rate: number | null }; live: { decisions: number; hold_rate: number | null; block_rate: number | null } } | null;

const PRESETS: { label: string; apply: (p: Pack) => Pack }[] = [
  { label: "Raise refund approval to ₹20,000", apply: (p) => tweak(p, "refunds-20k", (r) => r.id === "refund-above-threshold" ? { ...r, when: { ...r.when, amount_greater_than: 20000 } } : r) },
  { label: "Lower refund approval to ₹2,000", apply: (p) => tweak(p, "refunds-2k", (r) => r.id === "refund-above-threshold" ? { ...r, when: { ...r.when, amount_greater_than: 2000 } } : r) },
  { label: "Drop the injection deny rule", apply: (p) => ({ version: "no-injection-rule", policies: p.policies.filter((r) => r.id !== "injected-instruction-privileged-action") }) },
  { label: "Deny all external email", apply: (p) => ({ version: "deny-external-email", policies: [...p.policies.filter((r) => r.id !== "external-email-approval"),
      { id: "external-email-deny", description: "External email is blocked.", when: { action: "email.send", target_external: true }, decision: "deny" }] }) },
];

function tweak(p: Pack, version: string, fn: (r: Rule) => Rule): Pack {
  return { version, policies: p.policies.map(fn) };
}

const pct = (v: number | null | undefined) => (v === null || v === undefined ? "—" : `${(v * 100).toFixed(1)}%`);
const metricValue = (metric: string, v: number | null) =>
  v === null ? "—" : metric.includes("cost") ? `₹${v.toFixed(4)}` : metric.includes("latency") ? `${v.toFixed(1)} ms` : pct(v);

function Matrix({ transitions }: { transitions: Record<string, Record<string, number>> }) {
  const decisions = Array.from(new Set(Object.entries(transitions).flatMap(([a, row]) => [a, ...Object.keys(row)])));
  return (
    <table className="matrix">
      <thead><tr><th>live ↓ / candidate →</th>{decisions.map((d) => <th key={d}>{d.replaceAll("_", " ")}</th>)}</tr></thead>
      <tbody>
        {decisions.map((a) => (
          <tr key={a}><th>{a.replaceAll("_", " ")}</th>{decisions.map((b) => {
            const n = transitions[a]?.[b] ?? 0;
            return <td key={b} className={n && a !== b ? "flip" : ""}>{n || ""}</td>;
          })}</tr>
        ))}
      </tbody>
    </table>
  );
}

function RelaxationList({ flips }: { flips: Flip[] }) {
  // Group identical flips so twenty ₹18,000 refunds read as one line with a count.
  const groups = new Map<string, { flip: Flip; count: number }>();
  for (const f of flips) {
    const key = [f.action, f.amount, f.before, f.after, f.before_policy, f.after_policy, f.source].join("|");
    const g = groups.get(key);
    if (g) g.count += 1; else groups.set(key, { flip: f, count: 1 });
  }
  if (groups.size === 0) return null;
  return (
    <>
      <p className="eyebrow" style={{ marginTop: 14 }}>DECISIONS THAT BECOME LESS STRICT</p>
      <div className="data-list compact flips">
        {Array.from(groups.values()).slice(0, 8).map(({ flip: f, count }, i) => (
          <div className="data-row flip-row" key={i}>
            <div><b>{f.action}{f.amount ? ` · ₹${f.amount.toLocaleString()}` : ""}</b><span>{f.source}{f.tenant_id ? ` · ${f.tenant_id}` : ""} · ×{count}</span></div>
            <span className="row-gap nowrap"><DecisionPill decision={f.before} /> → <DecisionPill decision={f.after} /></span>
            <small><code>{f.before_policy}</code> → <code>{f.after_policy}</code></small>
          </div>
        ))}
      </div>
    </>
  );
}

export function PolicyRollout() {
  const [live, setLive] = useState<Pack | null>(null);
  const [text, setText] = useState("");
  const [impact, setImpact] = useState<Impact | null>(null);
  const [shadow, setShadow] = useState<Shadow | null>(null);
  const [canary, setCanary] = useState<Canary>(null);
  const [tenants, setTenants] = useState("zenbank");
  const [ack, setAck] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function refresh() {
    const [p, s, c] = await Promise.all([sfGet<Pack>("policies"), sfGet<Shadow>("policies/shadow"), sfGet<{ canary: Canary }>("policies/canary")]);
    setLive(p);
    setShadow(s);
    setCanary(c.canary);
    return p;
  }
  useEffect(() => {
    refresh().then((p) => setText(JSON.stringify(PRESETS[0].apply(p), null, 2))).catch((e) => setError(e.message));
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  function candidate(): Pack {
    const parsed = JSON.parse(text) as Pack;
    if (!parsed.version || !Array.isArray(parsed.policies)) throw new Error("Candidate must have 'version' and 'policies'");
    return parsed;
  }

  async function act(name: string, fn: () => Promise<void>) {
    setBusy(name);
    setError(null);
    try {
      await fn();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(null);
    }
  }

  const banner = impact ? ({ unsafe: "danger", review: "warn", tightening: "info", no_change: "good" } as const)[impact.verdict] : "good";
  return (
    <section className="panel">
      <PanelHead eyebrow="CHANGE MANAGEMENT" title="Impact analysis · shadow mode · canary" badge={live?.version} />
      <p className="hint">Edit a candidate pack, see exactly which recorded decisions would flip and whether release gates regress, then shadow it on live traffic or canary it for a tenant. Packs that loosen recorded decisions cannot be enforced without explicit acknowledgement.</p>
      <div className="chips">
        {PRESETS.map((p) => <button key={p.label} className="chip" disabled={!live} onClick={() => live && setText(JSON.stringify(p.apply(live), null, 2))}>{p.label}</button>)}
      </div>
      <textarea className="code-input" rows={10} value={text} onChange={(e) => setText(e.target.value)} spellCheck={false} aria-label="Candidate policy pack JSON" />
      <div className="form inline">
        <button className="primary" disabled={!!busy} onClick={() => act("impact", async () => setImpact(await sfPost<Impact>("policies/impact", candidate())))}>
          <Radar size={16} /> {busy === "impact" ? "Analyzing…" : "Analyze impact"}
        </button>
        <button disabled={!!busy} onClick={() => act("shadow", async () => { setShadow(await sfPost<Shadow>("policies/shadow", candidate())); })}><Eye size={16} /> Start shadow</button>
        {shadow?.active && <button disabled={!!busy} onClick={() => act("stop", async () => { await sfPost("policies/shadow/stop"); await refresh(); })}>Stop shadow</button>}
        <input value={tenants} onChange={(e) => setTenants(e.target.value)} placeholder="canary tenants (comma separated)" aria-label="Canary tenants" />
        <label className="check inline-check"><input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} /> I acknowledge relaxations</label>
        <button disabled={!!busy} onClick={() => act("canary", async () => {
          setCanary(await sfPost<Canary>("policies/canary", { ...candidate(), tenants: tenants.split(",").map((t) => t.trim()).filter(Boolean), acknowledge_relaxations: ack }));
        })}><GitBranch size={16} /> Start canary</button>
      </div>
      <ErrorNote error={error} />

      {(shadow?.active || shadow?.decisions) ? (
        <div className="callout">
          <b>Shadow {shadow.active ? "running" : "stopped"}: {shadow.version}</b>
          <span>{shadow.decisions} live decisions compared · agreement {pct(shadow.agreement_rate)} · {shadow.looser} looser · {shadow.tighter} stricter
            <button className="link-button" onClick={() => act("refresh", async () => { await refresh(); })}> refresh</button></span>
          {shadow.disagreements.slice(0, 4).map((d, i) => (
            <span key={i}><code>{d.action}</code> {d.amount ? `₹${d.amount}` : ""} live <DecisionPill decision={d.live} /> shadow <DecisionPill decision={d.shadow} /></span>
          ))}
        </div>
      ) : null}

      {canary && (
        <div className={`callout ${canary.anomalous ? "danger" : "warn"}`}>
          <b>Canary {canary.version} → {canary.tenants.join(", ") || `${canary.percent}% of sessions`}</b>
          <span>canary {canary.canary.decisions} decisions (hold {pct(canary.canary.hold_rate)}, block {pct(canary.canary.block_rate)}) · live {canary.live.decisions} (hold {pct(canary.live.hold_rate)}, block {pct(canary.live.block_rate)}) · shift {canary.strictness_shift === null ? "—" : `${(canary.strictness_shift * 100).toFixed(0)} pts`}</span>
          <span className="row-gap">
            <button className="primary" onClick={() => act("promote", async () => { await sfPost("policies/canary/promote", { acknowledge_relaxations: ack }); await refresh(); })}><Rocket size={14} /> Promote to live</button>
            <button onClick={() => act("rollback", async () => { await sfPost("policies/canary/rollback"); await refresh(); })}><Undo2 size={14} /> Roll back</button>
          </span>
        </div>
      )}

      {impact && (
        <div className="impact">
          <div className={`release-banner ${banner === "info" ? "good" : banner}`}>
            Verdict: <b>{impact.verdict.replaceAll("_", " ").toUpperCase()}</b> · {impact.summary} <small>({impact.candidate_version} vs live · {impact.agent_versions.length} agent versions)</small>
          </div>
          <div className="kv-row">
            <KV label="Rules added">{impact.diff.added.join(", ") || "—"}</KV>
            <KV label="Rules removed">{impact.diff.removed.join(", ") || "—"}</KV>
            <KV label="Rules changed">{impact.diff.changed.map((c) => `${c.id} (${c.fields.join(", ")})`).join("; ") || "—"}</KV>
          </div>
          <div className="two-col">
            {impact.evaluation_corpus && (
              <div>
                <p className="eyebrow">EVALUATION CORPUS · {impact.evaluation_corpus.records} DECISIONS</p>
                <Matrix transitions={impact.evaluation_corpus.transitions} />
                <p className="hint">{impact.evaluation_corpus.relaxed} relaxed · {impact.evaluation_corpus.tightened} tightened{impact.evaluation_corpus.dead_rules.length ? ` · rules that never matched: ${impact.evaluation_corpus.dead_rules.join(", ")}` : ""}</p>
              </div>
            )}
            {impact.live_history && (
              <div>
                <p className="eyebrow">LIVE HISTORY · {impact.live_history.records} DECISIONS</p>
                {impact.live_history.records ? <Matrix transitions={impact.live_history.transitions} /> : <div className="empty">No live decisions recorded yet.</div>}
                <p className="hint">{impact.live_history.relaxed} relaxed · {impact.live_history.tightened} tightened</p>
              </div>
            )}
          </div>
          <RelaxationList flips={[...(impact.live_history?.relaxation_examples ?? []), ...(impact.evaluation_corpus?.relaxation_examples ?? [])]} />
          {impact.release_gates && (
            <>
              <p className="eyebrow" style={{ marginTop: 18 }}>SECOND-ORDER EFFECT · EVERY AGENT RE-RUN UNDER THE CANDIDATE</p>
              <div className="data-list compact">
                {Object.entries(impact.release_gates).map(([version, g]) => {
                  const regressed = g.gates.filter((x) => x.regressed);
                  return (
                    <div className="data-row case" key={version}>
                      <div><b>{version}</b><span>{g.live_passed} → {g.candidate_passed} of {g.cases} cases · newly failing: {g.newly_failing_cases.map((c) => c.case_id).join(", ") || "none"}</span></div>
                      <span className={`decision ${g.release_regressed ? "danger" : g.candidate_decision === "approved" ? "good" : "warn"}`}>{g.live_decision} → {g.candidate_decision}</span>
                      <small>{regressed.length ? regressed.map((x) => `${x.metric.replaceAll("_", " ")} ${metricValue(x.metric, x.live)} → ${metricValue(x.metric, x.candidate)}`).join(" · ") : "no gate regressed"}</small>
                      <small>{impact.regressed_versions.includes(version) ? "⚠ regression" : ""}</small>
                    </div>
                  );
                })}
              </div>
            </>
          )}
        </div>
      )}
    </section>
  );
}
