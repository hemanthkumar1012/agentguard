-- SentinelForge: session guard, policy rollout (decision log, shadow, canary), adaptive red-team.

-- Durable decision log: policy inputs for replay / impact analysis. Never raw content or credentials.
create table if not exists policy_decision_log (
  record_id text primary key,
  recorded_at timestamptz not null default now(),
  agent_id text not null,
  tenant_id text,
  action text not null,
  target text not null,
  request jsonb not null,               -- ActionRequest minus content/credential fields, payload redacted
  risk_score numeric(6,2) not null,
  findings jsonb not null default '[]'::jsonb,
  injection_score integer not null default 0,
  injection_detected boolean not null default false,
  session_risk numeric(8,2) not null default 0,
  baseline jsonb not null,
  live_decision text not null,
  live_policy_id text,
  pack_version text not null,
  shadow_decision text,
  shadow_policy_id text,
  source text not null default 'live' check (source in ('live','evaluation'))
);
create index if not exists policy_decision_log_tenant_idx on policy_decision_log(tenant_id, recorded_at desc);
create index if not exists policy_decision_log_action_idx on policy_decision_log(action, recorded_at desc);
create index if not exists policy_decision_log_shadow_idx on policy_decision_log(shadow_decision) where shadow_decision is not null;

create table if not exists policy_rollout_events (
  id uuid primary key default gen_random_uuid(),
  event text not null check (event in ('shadow_started','shadow_stopped','canary_started','canary_promoted','canary_rolled_back')),
  version text not null,
  details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

-- Session guard: per-session risk and trips. The audit ledger already records
-- session.circuit_breaker and agent.quarantined events in the hash chain.
create table if not exists agent_sessions (
  session_id text primary key,
  agent_id text not null,
  agent_version text,
  tenant_id text,
  risk numeric(8,2) not null default 0,
  actions integer not null default 0,
  elevated boolean not null default false,
  tripped boolean not null default false,
  tripped_at timestamptz,
  signals jsonb not null default '[]'::jsonb,
  started_at timestamptz not null default now()
);
create index if not exists agent_sessions_tripped_idx on agent_sessions(tripped, started_at desc);
create index if not exists agent_sessions_agent_idx on agent_sessions(agent_id, started_at desc);

create table if not exists session_sequence_models (
  agent_version text primary key,
  transitions jsonb not null,           -- {prev: {next: count}}
  sequences integer not null,
  trained_at timestamptz not null default now()
);

-- Adaptive red-team runs and the variants worth keeping as regression cases.
create table if not exists redteam_fuzz_runs (
  fuzz_id text primary key,
  version_id text not null,
  params jsonb not null,
  totals jsonb not null,
  summary jsonb not null,
  started_at timestamptz not null,
  finished_at timestamptz
);
create table if not exists redteam_discovered_cases (
  fuzz_id text not null references redteam_fuzz_runs(fuzz_id) on delete cascade,
  case_id text not null,
  goal text not null,
  operators jsonb not null,
  detected boolean not null,
  resisted boolean not null,
  contained boolean not null,
  case_json jsonb not null,
  primary key (fuzz_id, case_id)
);

alter table policy_decision_log enable row level security;
alter table policy_rollout_events enable row level security;
alter table agent_sessions enable row level security;
alter table session_sequence_models enable row level security;
alter table redteam_fuzz_runs enable row level security;
alter table redteam_discovered_cases enable row level security;
