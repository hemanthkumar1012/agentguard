// Typed client for the console proxy (/api/sf/* -> SentinelForge /api/v1/*).

export type Observation = {
  action: string;
  args: Record<string, unknown>;
  decision: string;
  executed: boolean;
  reason: string;
  output?: unknown;
  error?: string | null;
  approval_id?: string | null;
  policy_id?: string | null;
  derived_from_untrusted?: boolean;
};

export type RunResult = {
  run_id: string;
  trace_id: string;
  version_id: string;
  status: string;
  output: string | null;
  observations: Observation[];
  approval_id: string | null;
  tokens: number;
  cost_inr: number;
};

export type Span = {
  span_id: string;
  parent_id: string | null;
  kind: string;
  name: string;
  started_at: string;
  duration_ms: number;
  status: string;
  attributes: Record<string, any>;
};

export type TraceSummary = {
  trace_id: string;
  tenant_id: string | null;
  user_id: string | null;
  agent_version: string | null;
  model: string | null;
  status: string;
  input: string;
  started_at: string;
  duration_ms: number;
  tools: string[];
  policies: string[];
  input_tokens: number;
  output_tokens: number;
  cost_inr: number;
  tool_calls: number;
  tool_errors: number;
  blocked_actions: number;
  max_risk: number;
  decisions: Record<string, number>;
};

export type TraceDetail = TraceSummary & {
  output: string | null;
  prompt_version: string | null;
  spans: Span[];
  tags: Record<string, any>;
  audit_events: { event_id: string; decision: string; policy_id: string | null; event_hash: string; reason: string }[];
  approvals: { approval_id: string; status: string; approver_role: string | null; decided_by: string | null; action: string }[];
};

export type Approval = {
  approval_id: string;
  requested_by: string;
  status: string;
  expires_at: string;
  decided_by: string | null;
  decision_note: string | null;
  approver_role: string | null;
  context: Record<string, any>;
};

export type AgentVersion = {
  version_id: string;
  agent_name: string;
  description: string;
  model: string;
  prompt_version: string;
  planner: string;
  status: string;
  agent_id: string;
  behavior: Record<string, unknown>;
  last_evaluation_id: string | null;
};

export type Gate = { metric: string; threshold: number; comparator: string; critical: boolean; value: number | null; passed: boolean };

export type EvaluationBrief = {
  evaluation_id: string;
  version_id: string;
  started_at: string;
  status: string;
  release_decision: string;
  summary: {
    cases: number;
    passed: number;
    pass_rate: number;
    metrics: Record<string, number | null>;
    by_dataset: Record<string, { total: number; passed: number }>;
    by_attack_type: Record<string, { total: number; passed: number }>;
    total_cost_inr: number;
    critical_failures: string[];
  };
  gates: Gate[];
};

export type CaseResult = {
  case_id: string;
  dataset: string;
  attack_type: string | null;
  input_source: string | null;
  severity: string;
  passed: boolean;
  failures: string[];
  output: string | null;
  attempted: { action: string; decision: string; executed: boolean; policy_id: string | null }[];
  trace_id: string;
  remediation: string | null;
};

export async function sfGet<T>(path: string, params?: Record<string, string | undefined>): Promise<T> {
  const query = params
    ? "?" + new URLSearchParams(Object.entries(params).filter(([, v]) => v) as [string, string][]).toString()
    : "";
  const res = await fetch(`/api/sf/${path}${query}`, { cache: "no-store" });
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail ?? `Request failed (${res.status})`);
  return res.json();
}

export async function sfPost<T>(path: string, body: unknown = {}): Promise<T> {
  const res = await fetch(`/api/sf/${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail ?? `Request failed (${res.status})`);
  return res.json();
}

export function decisionTone(decision: string): "good" | "warn" | "danger" | "info" {
  if (decision === "block" || decision === "rate_limit" || decision === "denied_by_approver") return "danger";
  if (decision === "require_approval" || decision === "escalate_to_human") return "warn";
  if (decision === "allow_with_redaction") return "info";
  return "good";
}

export function pct(value: number | null | undefined): string {
  return value === null || value === undefined ? "—" : `${(value * 100).toFixed(1)}%`;
}

export function inr(value: number | null | undefined): string {
  return value === null || value === undefined ? "—" : `₹${value.toFixed(value < 1 ? 4 : 2)}`;
}

export const METRIC_LABELS: Record<string, string> = {
  task_success: "Task success",
  tool_selection: "Tool selection",
  tool_correctness: "Tool argument correctness",
  grounding: "Grounding",
  injection_resistance: "Injection resistance (agent)",
  containment: "Containment (gateway)",
  privacy: "Privacy",
  policy_compliance: "Policy compliance",
  reliability: "Reliability",
  avg_cost_per_task_inr: "Cost per task",
  p95_latency_ms: "p95 latency",
};
