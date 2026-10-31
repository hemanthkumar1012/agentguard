"use client";

import { Area, AreaChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

export type RiskPoint = { trace_id: string; started_at: string; max_risk: number; agent_version: string | null };

// Max gateway risk per agent run (most recent 50 runs) from /observability/stats.
export function RiskChart({ points = [] }: { points?: RiskPoint[] }) {
  const data = points.map((p, i) => ({ run: i + 1, risk: Math.round(p.max_risk), version: p.agent_version }));
  if (data.length === 0) {
    return <div className="empty" style={{ height: 120, marginTop: 24 }}>No agent runs yet.</div>;
  }
  return (
    <div style={{ width: "100%", height: 120, marginTop: 24, marginBottom: 16 }}>
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ top: 5, right: 0, left: -25, bottom: 0 }}>
          <defs>
            <linearGradient id="colorRisk" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#ef4444" stopOpacity={0.4} />
              <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
            </linearGradient>
          </defs>
          <XAxis dataKey="run" axisLine={false} tickLine={false} tick={{ fill: "#52525b", fontSize: 10 }} />
          <YAxis domain={[0, 100]} axisLine={false} tickLine={false} tick={{ fill: "#52525b", fontSize: 10 }} />
          <Tooltip
            contentStyle={{ backgroundColor: "#111", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 8, fontSize: 12 }}
            formatter={(value, _name, item) => [String(value), `max risk · ${(item as { payload?: { version?: string } })?.payload?.version ?? ""}`]}
            labelFormatter={(label) => `Run ${String(label)}`}
          />
          <Area type="monotone" dataKey="risk" stroke="#ef4444" strokeWidth={2} fillOpacity={1} fill="url(#colorRisk)" />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
