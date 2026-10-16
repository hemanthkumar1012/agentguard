"use client";

import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";

const COLORS = ["#34d399", "#fbbf24", "#f87171"];

export function DecisionChart({
  allow,
  approval,
  block,
}: {
  allow: number;
  approval: number;
  block: number;
}) {
  const data = [
    { name: "Allow", value: allow || 0 },
    { name: "Approval", value: approval || 0 },
    { name: "Block", value: block || 0 },
  ];
  const total = allow + approval + block;

  if (total === 0) {
    return (
      <div style={{ textAlign: "center", padding: "24px 0", color: "var(--text-muted)", fontSize: 13 }}>
        No decisions yet
      </div>
    );
  }

  return (
    <div style={{ display: "flex", alignItems: "center", gap: 20 }}>
      <div style={{ width: 120, height: 120 }}>
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              cx="50%"
              cy="50%"
              innerRadius={36}
              outerRadius={54}
              paddingAngle={3}
              dataKey="value"
              stroke="none"
            >
              {data.map((_, i) => (
                <Cell key={i} fill={COLORS[i]} />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                backgroundColor: "#0f1218",
                border: "1px solid rgba(255,255,255,0.1)",
                borderRadius: 8,
                fontSize: 12,
              }}
            />
          </PieChart>
        </ResponsiveContainer>
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 8, flex: 1 }}>
        {data.map((d, i) => (
          <div key={d.name} style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13 }}>
            <span
              style={{
                width: 8,
                height: 8,
                borderRadius: 2,
                background: COLORS[i],
                flexShrink: 0,
              }}
            />
            <span style={{ color: "var(--text-secondary)", flex: 1 }}>{d.name}</span>
            <span style={{ fontWeight: 600, fontFamily: "var(--font-mono)", fontSize: 12 }}>
              {d.value}
            </span>
            <span style={{ color: "var(--text-muted)", fontSize: 11, minWidth: 32, textAlign: "right" }}>
              {total ? Math.round((d.value / total) * 100) : 0}%
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
