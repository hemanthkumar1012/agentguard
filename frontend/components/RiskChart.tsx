"use client";

import { Area, AreaChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

// Simulated risk data over time to demonstrate the visual capability
const data = [
  { time: "00:00", risk: 20 },
  { time: "04:00", risk: 22 },
  { time: "08:00", risk: 45 },
  { time: "12:00", risk: 30 },
  { time: "16:00", risk: 75 }, // Security Event Spike
  { time: "20:00", risk: 25 },
  { time: "24:00", risk: 20 },
];

export function RiskChart() {
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
          <XAxis 
            dataKey="time" 
            axisLine={false} 
            tickLine={false} 
            tick={{ fill: "#52525b", fontSize: 11 }} 
            dy={10} 
          />
          <YAxis 
            axisLine={false} 
            tickLine={false} 
            tick={{ fill: "#52525b", fontSize: 11 }} 
          />
          <Tooltip 
            contentStyle={{ backgroundColor: "#0a0a0a", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 8, color: "#fff", fontSize: 12 }}
            itemStyle={{ color: "#ef4444", fontWeight: 600 }}
            cursor={{ stroke: 'rgba(255,255,255,0.1)', strokeWidth: 1, strokeDasharray: '4 4' }}
          />
          <Area 
            type="monotone" 
            dataKey="risk" 
            stroke="#ef4444" 
            strokeWidth={2}
            fillOpacity={1} 
            fill="url(#colorRisk)" 
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
