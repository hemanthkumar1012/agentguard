from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
from threading import Lock
from uuid import uuid4


@dataclass
class Approval:
    approval_id: str
    event_id: str | None
    requested_by: str
    request_fingerprint: str
    status: str
    decision_note: str | None
    expires_at: datetime
    decided_by: str | None = None
    decided_at: datetime | None = None
    consumed_at: datetime | None = None


class ApprovalStore:
    def __init__(self, ttl_seconds: int = 900, store=None):
        self.ttl_seconds = ttl_seconds
        self.store = store
        self._items: dict[str, Approval] = {}
        self._lock = Lock()

    @staticmethod
    def fingerprint(request) -> str:
        payload = {
            "agent_id": request.agent_id,
            "action": request.action,
            "target": request.target,
            "data_classification": request.data_classification,
            "risk_score": request.risk_score,
            "content": request.content,
            "tool": request.tool,
            "credential_id": request.credential_id,
            "correlation_id": request.correlation_id,
            "execution_payload": request.execution_payload,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def create(self, requested_by: str, event_id: str | None = None, request_fingerprint: str = "") -> Approval:
        approval = Approval(
            approval_id=f"apr_{uuid4().hex[:16]}",
            event_id=event_id,
            requested_by=requested_by,
            request_fingerprint=request_fingerprint,
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
        with self._lock:
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

    def validate_approved(self, approval_id: str, request) -> Approval:
        approval = self.get(approval_id)
        if approval is None:
            raise ValueError("Approval not found")
        if approval.status != "approved":
            raise ValueError(f"Approval is {approval.status}")
        if approval.consumed_at is not None:
            raise ValueError("Approval has already been consumed")
        if approval.expires_at <= datetime.now(timezone.utc):
            approval.status = "expired"
            if self.store is not None:
                self.store.update_approval(approval)
            raise ValueError("Approval has expired")
        if approval.request_fingerprint != self.fingerprint(request):
            raise ValueError("Approval does not match this request")
        return approval

    def consume(self, approval_id: str, request) -> Approval:
        with self._lock:
            approval = self.validate_approved(approval_id, request)
            approval.status = "consumed"
            approval.consumed_at = datetime.now(timezone.utc)
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
