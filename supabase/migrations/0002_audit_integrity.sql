-- Add tamper-evident hash chaining to the security event ledger.
-- Existing rows receive the GENESIS marker; newly appended events chain from
-- the previous event hash at the application boundary.

alter table security_events
  add column if not exists previous_hash text not null default 'GENESIS',
  add column if not exists event_hash text not null default '';

create index if not exists security_events_hash_idx
  on security_events(event_hash);

-- Security events are forensic records: clients must never update or delete
-- them after insertion. The server-side service role may insert new events.
create or replace function prevent_security_event_mutation()
returns trigger
language plpgsql
as $$
begin
  raise exception 'security_events is append-only';
end;
$$;

drop trigger if exists security_events_immutable on security_events;
create trigger security_events_immutable
before update or delete on security_events
for each row execute function prevent_security_event_mutation();
