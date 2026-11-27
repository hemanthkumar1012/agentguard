-- One linear audit chain even with several writers (uvicorn workers, replicas).
--
-- Before: each worker took the previous hash from its own memory, so two workers chained from the
-- same event and the chain forked on the first pair of writes (found 2026-11-27, see
-- docs/findings-log.md). Now every event carries the next sequence number and this unique index
-- rejects the second writer; the ledger loads the events it missed and retries on top of them.

alter table security_events add column if not exists seq bigint;

-- Number the existing rows in the order they were written. security_events is append-only
-- (trigger from 0002), so the trigger is paused for this one backfill and switched back on.
alter table security_events disable trigger security_events_immutable;

with ordered as (
  select id, row_number() over (order by created_at, id) as rn
  from security_events
  where seq is null
)
update security_events s
set seq = o.rn + coalesce((select max(seq) from security_events), 0)
from ordered o
where s.id = o.id;

alter table security_events enable trigger security_events_immutable;

alter table security_events alter column seq set not null;
create unique index if not exists security_events_seq_key on security_events(seq);

-- Rows written before this migration by several workers may already be forked; verification will
-- report that history. From the first new sequence number on, the chain is linear.
