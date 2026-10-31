"use client";

type StreamEvent = { event_id: string; decision: string; action: string; agent_id: string; reason: string; created_at: string; policy_id?: string | null };

const TAG: Record<string, string> = {
  allow: "[OK]", block: "[BLOCK]", require_approval: "[HOLD]", escalate_to_human: "[ESCALATE]",
  allow_with_redaction: "[REDACT]", rate_limit: "[THROTTLE]",
};

// Live tail of the most recent audit events from the control-plane snapshot.
export function TerminalStream({ events = [] }: { events?: StreamEvent[] }) {
  const lines = [...events].reverse().slice(-8);
  return (
    <div className="terminal" aria-live="polite">
      {lines.length === 0 ? (
        <div className="terminal-line muted">Waiting for gateway decisions…</div>
      ) : (
        lines.map((e) => (
          <div className="terminal-line" key={e.event_id}>
            <span className="muted">{new Date(e.created_at).toISOString().split("T")[1].slice(0, 8)}</span>{" "}
            <span className={`tag ${e.decision}`}>{TAG[e.decision] ?? `[${e.decision}]`}</span>{" "}
            {e.action} {e.policy_id ? `(${e.policy_id})` : ""} — {e.reason}
          </div>
        ))
      )}
    </div>
  );
}
