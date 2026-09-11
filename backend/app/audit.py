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
    created_at: datetime


class AuditLedger:
    """Append-only interface for security decisions.

    This in-memory implementation is deliberately small; the same contract
    will later be persisted to PostgreSQL/Supabase.
    """

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []

    def append(
        self,
        *,
        agent_id: str,
        action: str,
        target: str,
        decision: str,
        risk_score: float,
        reason: str,
    ) -> AuditEvent:
        event = AuditEvent(
            event_id=f"evt_{uuid4().hex[:16]}",
            agent_id=agent_id,
            action=action,
            target=target,
            decision=decision,
            risk_score=risk_score,
            reason=reason,
            created_at=datetime.now(timezone.utc),
        )
        self._events.append(event)
        return event

    def list_events(self) -> list[dict]:
        return [asdict(event) for event in reversed(self._events)]
