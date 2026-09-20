-- AgentGuard durable PostgreSQL/Supabase schema.
-- The API currently uses an in-memory adapter for zero-config local runs.
-- This migration defines the production persistence contract.

create extension if not exists pgcrypto;

create table if not exists agents (
  id uuid primary key default gen_random_uuid(), agent_id text unique not null,
  name text not null, owner text not null, environment text not null default 'development',
  status text not null default 'active' check (status in ('active','suspended','revoked')),
  created_at timestamptz not null default now()
);
create table if not exists agent_permissions (
  agent_id uuid not null references agents(id) on delete cascade, permission text not null,
  primary key (agent_id, permission)
);
create table if not exists policy_rules (
  id uuid primary key default gen_random_uuid(), name text unique not null,
  effect text not null check (effect in ('allow','require_approval','block')),
  priority integer not null default 100, rule jsonb not null default '{}'::jsonb,
  enabled boolean not null default true, version text not null, created_at timestamptz not null default now()
);
create table if not exists security_events (
  id uuid primary key default gen_random_uuid(), event_id text unique not null,
  event_type text not null, agent_id text not null, action text not null, target text not null,
  tool text, credential_id text, correlation_id text,
  decision text not null check (decision in ('allow','require_approval','block')),
  risk_score numeric(5,2) not null check (risk_score between 0 and 100),
  risk_factors jsonb not null default '[]'::jsonb, data_findings jsonb not null default '[]'::jsonb,
  reason text not null, policy_version text not null, created_at timestamptz not null default now()
);
create index if not exists security_events_agent_created_idx on security_events(agent_id, created_at desc);
create index if not exists security_events_decision_idx on security_events(decision, created_at desc);
create index if not exists security_events_risk_idx on security_events(risk_score desc, created_at desc);
create table if not exists scoped_credentials (
  id uuid primary key default gen_random_uuid(), credential_id text unique not null,
  agent_id text not null, tool text not null, scopes jsonb not null default '[]'::jsonb,
  token_hash text not null, expires_at timestamptz not null, revoked_at timestamptz,
  created_at timestamptz not null default now()
);
create index if not exists scoped_credentials_lookup_idx on scoped_credentials(credential_id, agent_id, tool);
create table if not exists agent_relationships (
  id uuid primary key default gen_random_uuid(), source_agent_id text not null,
  target_agent_id text not null, scopes jsonb not null default '[]'::jsonb,
  enabled boolean not null default true, created_at timestamptz not null default now(),
  unique(source_agent_id, target_agent_id)
);
create table if not exists approvals (
  id uuid primary key default gen_random_uuid(), approval_id text unique not null,
  event_id text references security_events(event_id) on delete set null,
  requested_by text not null, status text not null default 'pending'
    check (status in ('pending','approved','denied','expired')),
  decided_by text, decision_note text, expires_at timestamptz, created_at timestamptz not null default now(), decided_at timestamptz
);

alter table agents enable row level security;
alter table agent_permissions enable row level security;
alter table policy_rules enable row level security;
alter table security_events enable row level security;
alter table scoped_credentials enable row level security;
alter table agent_relationships enable row level security;
alter table approvals enable row level security;

-- Client roles receive no direct access by default. Server-side service-role code
-- can bypass RLS; add explicit authenticated-operator policies after auth is wired.
create policy agents_server_only on agents for all using (false) with check (false);
create policy agent_permissions_server_only on agent_permissions for all using (false) with check (false);
create policy policy_rules_server_only on policy_rules for all using (false) with check (false);
create policy security_events_server_only on security_events for all using (false) with check (false);
create policy scoped_credentials_server_only on scoped_credentials for all using (false) with check (false);
create policy agent_relationships_server_only on agent_relationships for all using (false) with check (false);
create policy approvals_server_only on approvals for all using (false) with check (false);
