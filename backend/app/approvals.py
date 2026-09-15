from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import uuid4


@dataclass
class Approval:
    approval_id: str
    event_id: str | None
    requested_by: str
    status: str
    decision_note: str | None
    expires_at: datetime
    decided_by: str | None = None
    decided_at: datetime | None = None


class ApprovalStore:
    def __init__(self, ttl_seconds: int = 900, store=None):
        self.ttl_seconds = ttl_seconds
        self.store = store
        self._items: dict[str, Approval] = {}

    def create(self, requested_by: str, event_id: str | None = None) -> Approval:
        approval = Approval(
            approval_id=f"apr_{uuid4().hex[:16]}",
            event_id=event_id,
            requested_by=requested_by,
            status="pending",
            decision_note=None,
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=self.ttl_seconds),
        )
        if self.store is not None:
            self.store.insert_approval(approval)
        self._items[approval.approval_id] = approval
        return approval

    def get(self, approval_id: str) -> Approval | None:
        approval = self._items.get(approval_id)
        if approval is None and self.store is not None:
            approval = self.store.get_approval(approval_id)
            if approval is not None:
                self._items[approval_id] = approval
        if approval and approval.status == "pending" and approval.expires_at <= datetime.now(timezone.utc):
            approval.status = "expired"
            if self.store is not None:
                self.store.update_approval(approval)
        return approval

    def decide(self, approval_id: str, approved: bool, decided_by: str, note: str | None = None) -> Approval:
        approval = self.get(approval_id)
        if approval is None:
            raise KeyError("Approval not found")
        if approval.status != "pending":
            raise ValueError(f"Approval is already {approval.status}")
        approval.status = "approved" if approved else "denied"
        approval.decided_by = decided_by
        approval.decision_note = note
        approval.decided_at = datetime.now(timezone.utc)
        if self.store is not None:
            self.store.update_approval(approval)
        return approval

    def list(self) -> list[Approval]:
        if self.store is not None:
            persisted = self.store.list_approvals()
            for item in persisted:
                self._items[item.approval_id] = item
        for approval in self._items.values():
            self.get(approval.approval_id)
        return list(reversed(list(self._items.values())))
