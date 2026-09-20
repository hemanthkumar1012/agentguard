"use client";

import { useEffect, useState } from "react";

const SIMULATED_LOGS = [
  "[SYS] Gateway connection established.",
  "[AUTH] Token verified for agent-801.",
  "[OK] Action 'read_file' allowed (risk: 12).",
  "[WARN] High-risk payload detected in target context.",
  "[BLOCK] Action 'delete_user' blocked by policy 'Hard Block'.",
  "[SYS] Syncing telemetry to central control plane...",
  "[OK] Approval consumed by security_admin.",
  "[AUTH] Scoped credential issued for tool 'aws_cli'.",
];

export function TerminalStream() {
  const [logs, setLogs] = useState<string[]>(["[SYS] Initializing AgentGuard Security Stream..."]);

  useEffect(() => {
    let count = 0;
    const interval = setInterval(() => {
      setLogs((prev) => {
        const nextLog = SIMULATED_LOGS[count % SIMULATED_LOGS.length];
        const timestamp = new Date().toISOString().split("T")[1].substring(0, 8);
        const newLogs = [...prev, `${timestamp} ${nextLog}`];
        if (newLogs.length > 5) newLogs.shift();
        return newLogs;
      });
      count++;
    }, 3500);

    return () => clearInterval(interval);
  }, []);

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
          color: log.includes("[BLOCK]") || log.includes("[WARN]") ? "#ef4444" : 
                 log.includes("[OK]") ? "#10b981" : 
                 log.includes("[AUTH]") ? "#f59e0b" : "#3b82f6",
          transition: "opacity 0.5s ease"
        }}>
          {log}
        </div>
      ))}
      <div style={{ position: "absolute", bottom: 0, left: 0, right: 0, height: "20px", background: "linear-gradient(to top, #0a0a0a, transparent)", zIndex: 1 }} />
    </div>
  );
}
