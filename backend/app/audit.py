from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
from uuid import uuid4


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


class AuditLedger:
    """Append-only, hash-chained security event ledger with optional persistence."""

    def __init__(self, store=None) -> None:
        self._events: list[AuditEvent] = []
        self.store = store

    @staticmethod
    def _hash_payload(event: AuditEvent) -> str:
        payload = asdict(event)
        payload.pop("event_hash", None)
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
        previous_hash = self._events[-1].event_hash if self._events else "GENESIS"
        event = AuditEvent(
            event_id=f"evt_{uuid4().hex[:16]}",
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
            created_at=datetime.now(timezone.utc),
            previous_hash=previous_hash,
            event_hash="",
        )
        event = AuditEvent(**{**asdict(event), "event_hash": self._hash_payload(event)})
        self._events.append(event)
        if self.store is not None:
            self.store.insert_security_event(event)
        return event

    def verify_integrity(self) -> bool:
        previous_hash = "GENESIS"
        for event in self._events:
            if event.previous_hash != previous_hash or self._hash_payload(event) != event.event_hash:
                return False
            previous_hash = event.event_hash
        return True

    def list_events(self) -> list[dict]:
        return [asdict(event) for event in reversed(self._events)]

    def count(self) -> int:
        return len(self._events)
