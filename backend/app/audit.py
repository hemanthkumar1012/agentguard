from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
from threading import Lock
from uuid import uuid4


MAX_APPEND_ATTEMPTS = 8


class ChainConflict(Exception):
    """The store already holds an event at this sequence number: another writer appended first."""


class AuditWriteFailed(Exception):
    """The event could not be appended. Callers must treat the action as not authorised."""


@dataclass(frozen=True)
class AuditEvent:
    event_id: str
    agent_id: str
    action: str
    target: str
    decision: str
    risk_score: float
    reason: str
    risk_factors: tuple[str, ...]
    data_findings: tuple[str, ...]
    tool: str | None
    credential_id: str | None
    correlation_id: str | None
    policy_version: str
    event_type: str
    created_at: datetime
    previous_hash: str
    event_hash: str
    # Position in the chain. Not part of the hash (rows written before it existed still verify);
    # the store keeps it unique, which is what stops two writers from forking the chain.
    sequence: int = 0


class AuditLedger:
    """Append-only, hash-chained security event ledger with optional persistence.

    Several processes (uvicorn workers, replicas) can write to the same store. Each one used to
    take the previous hash from its own memory, so two workers chained from the same event and the
    chain forked on the first pair of writes. Now every event carries the next sequence number;
    the store rejects a duplicate (a unique index in Postgres), and the losing writer loads the
    events it missed and retries on top of them: optimistic concurrency, compare-and-swap on the head.
    """

    def __init__(self, store=None) -> None:
        self.store = store
        self._lock = Lock()
        self._events = self._load_events()
        self._initial_previous_hash = self.store.get_last_event_hash() if self.store and not self._events else None
        if self._initial_previous_hash is None:
            self._initial_previous_hash = "GENESIS"
        self.conflicts = 0  # how often another writer won the race; exposed for metrics and tests

    def _load_events(self) -> list[AuditEvent]:
        if self.store is None or not hasattr(self.store, "list_security_events"):
            return []
        return [self._from_row(row) for row in self.store.list_security_events()]

    @staticmethod
    def _from_row(row: dict) -> AuditEvent:
        created_at = row["created_at"]
        if isinstance(created_at, str):
            created_at = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        return AuditEvent(
            event_id=row["event_id"],
            agent_id=row["agent_id"],
            action=row["action"],
            target=row["target"],
            decision=row["decision"],
            risk_score=float(row["risk_score"]),
            reason=row["reason"],
            risk_factors=tuple(row.get("risk_factors") or []),
            data_findings=tuple(row.get("data_findings") or []),
            tool=row.get("tool"),
            credential_id=row.get("credential_id"),
            correlation_id=row.get("correlation_id"),
            policy_version=row["policy_version"],
            event_type=row["event_type"],
            created_at=created_at,
            previous_hash=row["previous_hash"],
            event_hash=row["event_hash"],
            sequence=int(row.get("seq") or 0),
        )

    @staticmethod
    def _hash_payload(event: AuditEvent) -> str:
        payload = asdict(event)
        payload.pop("event_hash", None)
        payload.pop("sequence", None)
        payload["risk_score"] = float(event.risk_score)
        payload["created_at"] = event.created_at.isoformat()
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def append(
        self,
        agent_id: str,
        action: str,
        target: str,
        decision: str,
        risk_score: float,
        reason: str,
        risk_factors: list[str] | tuple[str, ...] = (),
        data_findings: list[str] | tuple[str, ...] = (),
        tool: str | None = None,
        credential_id: str | None = None,
        correlation_id: str | None = None,
        policy_version: str = "2026.09",
        event_type: str = "authorization.decision",
    ) -> AuditEvent:
        event_id = f"evt_{uuid4().hex[:16]}"
        created_at = datetime.now(timezone.utc)
        with self._lock:
            for _ in range(MAX_APPEND_ATTEMPTS):
                previous_hash, sequence = self._head()
                event = AuditEvent(
                    event_id=event_id,
                    agent_id=agent_id,
                    action=action,
                    target=target,
                    decision=decision,
                    risk_score=risk_score,
                    reason=reason,
                    risk_factors=tuple(risk_factors),
                    data_findings=tuple(data_findings),
                    tool=tool,
                    credential_id=credential_id,
                    correlation_id=correlation_id,
                    policy_version=policy_version,
                    event_type=event_type,
                    created_at=created_at,
                    previous_hash=previous_hash,
                    event_hash="",
                    sequence=sequence,
                )
                event = AuditEvent(**{**asdict(event), "event_hash": self._hash_payload(event)})
                if self.store is not None:
                    try:
                        self.store.insert_security_event(event)
                    except ChainConflict:
                        self.conflicts += 1
                        self._catch_up()
                        continue
                self._events.append(event)
                return event
        raise AuditWriteFailed(f"audit append lost the race {MAX_APPEND_ATTEMPTS} times in a row")

    def _head(self) -> tuple[str, int]:
        if self._events:
            last = self._events[-1]
            return last.event_hash, last.sequence + 1
        return self._initial_previous_hash, 1

    def _catch_up(self) -> None:
        """Loads events other writers appended after our head, so the next attempt chains from them."""
        after = self._events[-1].sequence if self._events else 0
        if hasattr(self.store, "list_security_events_after"):
            rows = self.store.list_security_events_after(after)
        else:
            rows = [r for r in self.store.list_security_events() if int(r.get("seq") or 0) > after]
        self._events.extend(self._from_row(row) for row in rows)

    def verify_integrity(self) -> bool:
        previous_hash = self._initial_previous_hash
        for event in self._events:
            if event.previous_hash != previous_hash or self._hash_payload(event) != event.event_hash:
                return False
            previous_hash = event.event_hash
        return True

    def list_events(self) -> list[dict]:
        return [asdict(event) for event in reversed(self._events)]

    def count(self) -> int:
        return len(self._events)
