from dataclasses import asdict, dataclass
from datetime import datetime, timezone
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


class AuditLedger:
    """Append-only security event ledger with optional durable persistence."""

    def __init__(self, store=None) -> None:
        self._events: list[AuditEvent] = []
        self.store = store

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
        )
        self._events.append(event)
        if self.store is not None:
            self.store.insert_security_event(event)
        return event

    def list_events(self) -> list[dict]:
        return [asdict(event) for event in reversed(self._events)]

    def count(self) -> int:
        return len(self._events)
