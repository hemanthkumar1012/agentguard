-- Bind approvals to the exact authorization request and prevent replay.
alter table approvals
  add column if not exists request_fingerprint text not null default '',
  add column if not exists consumed_at timestamptz;

create index if not exists approvals_request_fingerprint_idx
  on approvals(request_fingerprint);

alter table approvals
  drop constraint if exists approvals_status_check;

alter table approvals
  add constraint approvals_status_check
  check (status in ('pending','approved','denied','expired','consumed'));
