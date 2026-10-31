"use client";

import { useEffect, useState } from "react";
import { Check, HelpCircle, RefreshCw, X } from "lucide-react";
import { Approval, RunResult, sfGet, sfPost } from "../../lib/sf";
import { DecisionPill, ErrorNote, KV, PageHeader, PanelHead, StatusPill, TraceLink } from "./ui";

const ROLES = ["finance_manager", "support_manager", "compliance_officer", "platform_admin", "admin"];

export function ApprovalInbox({ onOpenTrace }: { onOpenTrace: (id: string) => void }) {
  const [items, setItems] = useState<Approval[]>([]);
  const [showAll, setShowAll] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [resumed, setResumed] = useState<{ approvalId: string; result: RunResult }[]>([]);

  async function load() {
    try {
      const body = await sfGet<{ approvals: Approval[] }>("approvals");
      const order = (a: Approval) => (a.status === "pending" ? 0 : a.status === "info_requested" ? 1 : 2);
      setItems(body.approvals.sort((x, y) => order(x) - order(y)));
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    }
  }
  useEffect(() => { load(); }, []);

  const visible = showAll ? items : items.filter((a) => a.status === "pending" || a.status === "info_requested");
  return (
    <>
      <PageHeader eyebrow="HUMAN IN THE LOOP" title="Approval Inbox"
        sub="High-impact actions pause here. Approvals are bound to the exact request fingerprint, expire, and can be used once.">
        <button onClick={load}><RefreshCw size={16} /> Refresh</button>
      </PageHeader>
      <label className="check"><input type="checkbox" checked={showAll} onChange={(e) => setShowAll(e.target.checked)} /> Show decided approvals</label>
      <ErrorNote error={error} />
      {resumed.map(({ approvalId, result }) => (
        <div className="callout" key={approvalId}>
          <b>Run resumed after {approvalId} · {result.status.replaceAll("_", " ")}</b>
          <span>{result.output} · <TraceLink traceId={result.trace_id} onOpen={onOpenTrace} /></span>
        </div>
      ))}
      {visible.length === 0 ? <section className="panel"><div className="empty">Nothing waiting for a decision.</div></section> :
        visible.map((a) => (
          <ApprovalCard key={a.approval_id} approval={a} onChanged={load} onOpenTrace={onOpenTrace}
            onResumed={(result) => setResumed((prev) => [{ approvalId: a.approval_id, result }, ...prev].slice(0, 5))} />
        ))}
    </>
  );
}

function ApprovalCard({ approval, onChanged, onOpenTrace, onResumed }: {
  approval: Approval; onChanged: () => void; onOpenTrace: (id: string) => void; onResumed: (result: RunResult) => void;
}) {
  const c = approval.context ?? {};
  const [name, setName] = useState("");
  const [role, setRole] = useState(approval.approver_role ?? "admin");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const open = approval.status === "pending" || approval.status === "info_requested";

  async function decide(kind: "approve" | "reject" | "info") {
    if (!name.trim()) { setError("Enter your name so the decision is attributable."); return; }
    setBusy(true);
    setError(null);
    try {
      await sfPost(`approvals/${approval.approval_id}/decision`, {
        approved: kind === "approve", request_info: kind === "info", decided_by: name.trim(), decided_by_role: role, note: note || null,
      });
      if (kind !== "info" && c.trace_id) {
        // Resuming re-submits the exact request with the approval id; the gateway re-checks it.
        const result = await sfPost<RunResult>(`runs/${c.trace_id}/resume`).catch(() => null);
        if (result) onResumed(result);
      }
      onChanged();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel approval">
      <PanelHead eyebrow={`REQUESTED BY ${approval.requested_by}`} title={`${c.action ?? "action"} → ${c.target ?? ""}`}
        action={<StatusPill status={approval.status} />} />
      <div className="kv-row">
        <KV label="Decision"><DecisionPill decision={c.decision ?? "require_approval"} /></KV>
        <KV label="Approver role">{approval.approver_role ?? "any reviewer"}</KV>
        <KV label="Risk score">{c.risk_score !== undefined ? Math.round(c.risk_score) : "—"}</KV>
        <KV label="Policy">{c.policy_id ?? "—"}</KV>
        <KV label="Customer">{c.user_id ?? "—"} ({c.tenant_id ?? "—"})</KV>
        <KV label="Expires">{new Date(approval.expires_at).toLocaleTimeString()}</KV>
      </div>
      <KV label="Reason">{c.reason}</KV>
      <KV label="Proposed tool call"><code>{c.tool}:{c.action}({JSON.stringify(c.arguments ?? {})})</code></KV>
      {(c.risk_factors?.length > 0 || c.data_findings?.length > 0) && (
        <KV label="Evidence">{[...(c.risk_factors ?? []), ...(c.data_findings ?? []).map((f: string) => `finding:${f}`)].join(", ")}</KV>
      )}
      {c.trace_id && <KV label="Trace"><TraceLink traceId={c.trace_id} onOpen={onOpenTrace} /></KV>}
      {approval.decision_note && <KV label="Note">{approval.decision_note} {approval.decided_by ? `— ${approval.decided_by}` : ""}</KV>}

      {open && (
        <div className="form inline">
          <input placeholder="Your name" value={name} onChange={(e) => setName(e.target.value)} />
          <select value={role} onChange={(e) => setRole(e.target.value)}>
            {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
          </select>
          <input placeholder="Note (optional)" value={note} onChange={(e) => setNote(e.target.value)} />
          <button className="primary good" disabled={busy} onClick={() => decide("approve")}><Check size={16} /> Approve</button>
          <button className="danger" disabled={busy} onClick={() => decide("reject")}><X size={16} /> Reject</button>
          <button disabled={busy} onClick={() => decide("info")}><HelpCircle size={16} /> Request info</button>
        </div>
      )}
      <ErrorNote error={error} />
    </section>
  );
}
