-- SentinelForge: declarative policy decisions, approval context, traces,
-- agent versions and evaluation evidence.

-- 1. New gateway decisions. The original constraint only allowed three values,
--    so ALLOW_WITH_REDACTION / RATE_LIMIT / ESCALATE_TO_HUMAN events would fail to persist.
alter table security_events drop constraint if exists security_events_decision_check;
alter table security_events
  add constraint security_events_decision_check
  check (decision in ('allow','require_approval','block','allow_with_redaction','rate_limit','escalate_to_human'));

-- Optional audit fields. They are excluded from the hash when null, so chains
-- written before this migration keep verifying.
alter table security_events
  add column if not exists policy_id text,
  add column if not exists trace_id text,
  add column if not exists tenant_id text;
create index if not exists security_events_trace_idx on security_events(trace_id);
create index if not exists security_events_tenant_created_idx on security_events(tenant_id, created_at desc);
create index if not exists security_events_policy_idx on security_events(policy_id, created_at desc);

-- 2. Approval routing and the evidence an approver sees.
alter table approvals
  add column if not exists approver_role text,
  add column if not exists context jsonb not null default '{}'::jsonb;
alter table approvals drop constraint if exists approvals_status_check;
alter table approvals
  add constraint approvals_status_check
  check (status in ('pending','info_requested','approved','denied','expired','consumed'));
create index if not exists approvals_role_status_idx on approvals(approver_role, status);

-- 3. Agent run traces (spans stored inline; one row per run).
create table if not exists agent_traces (
  trace_id text primary key,
  tenant_id text,
  user_id text,
  agent_id text,
  agent_version text,
  model text,
  prompt_version text,
  status text not null,
  input text not null,
  output text,
  started_at timestamptz not null,
  ended_at timestamptz,
  duration_ms numeric(12,2),
  input_tokens integer not null default 0,
  output_tokens integer not null default 0,
  cost_inr numeric(12,6) not null default 0,
  blocked_actions integer not null default 0,
  max_risk numeric(5,2) not null default 0,
  policies jsonb not null default '[]'::jsonb,
  spans jsonb not null default '[]'::jsonb,
  tags jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);
create index if not exists agent_traces_tenant_started_idx on agent_traces(tenant_id, started_at desc);
create index if not exists agent_traces_version_started_idx on agent_traces(agent_version, started_at desc);
create index if not exists agent_traces_status_idx on agent_traces(status, started_at desc);
create index if not exists agent_traces_policies_idx on agent_traces using gin (policies);

-- 4. Versioned agents and evaluation evidence.
create table if not exists agent_versions (
  version_id text primary key,
  agent_name text not null,
  description text not null default '',
  model text not null,
  prompt_version text not null,
  system_prompt text not null,
  planner text not null check (planner in ('scripted','openai')),
  permissions jsonb not null default '[]'::jsonb,
  behavior jsonb not null default '{}'::jsonb,
  status text not null default 'candidate' check (status in ('candidate','released','blocked','superseded')),
  agent_id text,
  last_evaluation_id text,
  created_at timestamptz not null default now()
);

create table if not exists evaluation_runs (
  evaluation_id text primary key,
  version_id text not null references agent_versions(version_id) on delete cascade,
  datasets jsonb not null default '[]'::jsonb,
  repeats integer not null default 1,
  status text not null,
  release_decision text not null check (release_decision in ('pending','approved','blocked')),
  summary jsonb not null default '{}'::jsonb,
  gates jsonb not null default '[]'::jsonb,
  started_at timestamptz not null,
  finished_at timestamptz
);
create table if not exists evaluation_case_results (
  evaluation_id text not null references evaluation_runs(evaluation_id) on delete cascade,
  case_id text not null,
  dataset text not null,
  passed boolean not null,
  metrics jsonb not null default '{}'::jsonb,
  failures jsonb not null default '[]'::jsonb,
  trace_id text,
  output text,
  primary key (evaluation_id, case_id)
);
create index if not exists evaluation_case_failed_idx on evaluation_case_results(evaluation_id) where not passed;

create table if not exists policy_packs (
  version text primary key,
  rules jsonb not null,
  loaded_by text,
  loaded_at timestamptz not null default now()
);

-- Server-side only: the API uses the service key, so no anon/authenticated policies.
alter table agent_traces enable row level security;
alter table agent_versions enable row level security;
alter table evaluation_runs enable row level security;
alter table evaluation_case_results enable row level security;
alter table policy_packs enable row level security;
