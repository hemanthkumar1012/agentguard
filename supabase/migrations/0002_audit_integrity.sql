-- Add tamper-evident hash chaining to the security event ledger.
-- Existing rows receive the GENESIS marker; newly appended events chain from
-- the previous event hash at the application boundary.

alter table security_events
  add column if not exists previous_hash text not null default 'GENESIS',
  add column if not exists event_hash text not null default '';

create index if not exists security_events_hash_idx
  on security_events(event_hash);
