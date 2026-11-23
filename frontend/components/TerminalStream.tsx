"use client";

type StreamEvent = {
  event_id: string;
  agent_id: string;
  action: string;
  target: string;
  decision: string;
  risk_score: number;
  created_at: string;
};

const clock = (iso: string) => new Date(iso).toLocaleTimeString([], { hour12: false });

// Shows the latest real decisions from the control-plane snapshot (newest at the bottom).
// Earlier versions cycled through a fixed list of example lines; that was decoration, not data.
export function TerminalStream({ events }: { events: StreamEvent[] }) {
  const logs = events.length === 0
    ? ["[SYS] Waiting for the first security decision..."]
    : events.slice(0, 5).reverse().map(e =>
        `${clock(e.created_at)} [${e.decision.replace("_", " ").toUpperCase()}] ${e.action} by ${e.agent_id} -> ${e.target} (risk ${Math.round(e.risk_score)})`);

  return (
    <div style={{
      background: "#0a0a0a",
      border: "1px solid rgba(255,255,255,0.08)",
      borderRadius: "8px",
      padding: "16px",
      fontFamily: "var(--font-mono)",
      fontSize: "12px",
      color: "#3b82f6",
      marginTop: "24px",
      display: "flex",
      flexDirection: "column",
      gap: "8px",
      height: "140px",
      overflow: "hidden",
      position: "relative",
      boxShadow: "inset 0 0 10px rgba(0,0,0,0.5)"
    }}>
      <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: "20px", background: "linear-gradient(to bottom, #0a0a0a, transparent)", zIndex: 1 }} />
      {logs.map((log, i) => (
        <div key={i} style={{
          opacity: (i + 1) / logs.length,
          color: log.includes("[BLOCK]") ? "#ef4444" :
                 log.includes("[ALLOW]") ? "#10b981" :
                 log.includes("[REQUIRE APPROVAL]") ? "#f59e0b" : "#3b82f6",
          transition: "opacity 0.5s ease"
        }}>
          {log}
        </div>
      ))}
      <div style={{ position: "absolute", bottom: 0, left: 0, right: 0, height: "20px", background: "linear-gradient(to top, #0a0a0a, transparent)", zIndex: 1 }} />
    </div>
  );
}
