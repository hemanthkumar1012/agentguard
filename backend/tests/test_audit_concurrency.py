"""Several workers writing one audit chain must not fork it."""
from threading import Barrier, Lock, Thread

import pytest

from app.audit import AuditLedger, AuditWriteFailed, ChainConflict


class SharedChainStore:
    """Behaves like the Postgres table after migration 0004: `seq` is unique, inserts are atomic."""

    def __init__(self):
        self.rows: list[dict] = []
        self._lock = Lock()

    def _row(self, event):
        return {**event.__dict__, "risk_factors": list(event.risk_factors), "data_findings": list(event.data_findings),
                "created_at": event.created_at.isoformat(), "seq": event.sequence}

    def insert_security_event(self, event):
        with self._lock:
            if any(r["seq"] == event.sequence for r in self.rows):
                raise ChainConflict(f"duplicate seq {event.sequence}")
            self.rows.append(self._row(event))

    def get_last_event_hash(self):
        with self._lock:
            return max(self.rows, key=lambda r: r["seq"])["event_hash"] if self.rows else None

    def list_security_events(self):
        with self._lock:
            return sorted(self.rows, key=lambda r: r["seq"])

    def list_security_events_after(self, seq):
        return [r for r in self.list_security_events() if r["seq"] > seq]


def chain_is_linear(rows: list[dict]) -> bool:
    previous = "GENESIS"
    for expected_seq, row in enumerate(sorted(rows, key=lambda r: r["seq"]), start=1):
        if row["seq"] != expected_seq or row["previous_hash"] != previous:
            return False
        previous = row["event_hash"]
    return True


def append(ledger, i):
    return ledger.append("agt", "read", "crm", "allow", 1, f"event {i}")


def test_two_workers_writing_in_turn_keep_one_chain():
    # Before 2026-11-27 this forked on the second write: both workers chained from GENESIS.
    store = SharedChainStore()
    worker_a, worker_b = AuditLedger(store=store), AuditLedger(store=store)
    for i in range(10):
        append(worker_a if i % 2 == 0 else worker_b, i)
    assert chain_is_linear(store.rows)
    assert worker_b.conflicts >= 1                       # B lost the race and retried on top of A
    assert AuditLedger(store=store).verify_integrity()   # a restarted worker sees a valid chain


def test_many_threads_across_workers_never_fork_the_chain():
    store = SharedChainStore()
    workers = [AuditLedger(store=store) for _ in range(3)]
    threads_per_worker, writes = 3, 40
    start = Barrier(len(workers) * threads_per_worker)

    def run(ledger):
        start.wait()
        for i in range(writes):
            append(ledger, i)

    threads = [Thread(target=run, args=(w,)) for w in workers for _ in range(threads_per_worker)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(store.rows) == len(workers) * threads_per_worker * writes
    assert chain_is_linear(store.rows)
    assert AuditLedger(store=store).verify_integrity()


def test_tampering_is_still_detected_after_catching_up():
    store = SharedChainStore()
    append(AuditLedger(store=store), 0)
    store.rows[0]["reason"] = "rewritten"
    assert AuditLedger(store=store).verify_integrity() is False


def test_a_writer_that_keeps_losing_fails_closed():
    class AlwaysTaken(SharedChainStore):
        def insert_security_event(self, event):
            raise ChainConflict("taken")

    with pytest.raises(AuditWriteFailed):
        append(AuditLedger(store=AlwaysTaken()), 0)


def test_supabase_unique_violation_maps_to_chain_conflict():
    from app.supabase_store import SupabaseStore

    class APIError(Exception):     # shape of postgrest.exceptions.APIError
        def __init__(self, code):
            super().__init__({"code": code, "message": "duplicate key value violates unique constraint"})
            self.code = code

    store = SupabaseStore.__new__(SupabaseStore)
    store._insert_security_event = lambda event: (_ for _ in ()).throw(APIError("23505"))
    with pytest.raises(ChainConflict):
        store.insert_security_event(object())
    store._insert_security_event = lambda event: (_ for _ in ()).throw(APIError("42501"))
    with pytest.raises(APIError):
        store.insert_security_event(object())
