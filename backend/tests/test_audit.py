from app.audit import AuditLedger


class MemoryAuditStore:
    def __init__(self):
        self.events = []

    def list_security_events(self):
        return list(self.events)

    def get_last_event_hash(self):
        return self.events[-1]["event_hash"] if self.events else None

    def insert_security_event(self, event):
        self.events.append({
            "event_id": event.event_id,
            "agent_id": event.agent_id,
            "action": event.action,
            "target": event.target,
            "decision": event.decision,
            "risk_score": event.risk_score,
            "reason": event.reason,
            "risk_factors": list(event.risk_factors),
            "data_findings": list(event.data_findings),
            "tool": event.tool,
            "credential_id": event.credential_id,
            "correlation_id": event.correlation_id,
            "policy_version": event.policy_version,
            "event_type": event.event_type,
            "created_at": event.created_at.isoformat(),
            "previous_hash": event.previous_hash,
            "event_hash": event.event_hash,
        })


def test_audit_ledger_is_append_only_and_newest_first():
    ledger = AuditLedger()
    ledger.append(
        agent_id="agt_demo",
        action="read_customer",
        target="customer/123",
        decision="allow",
        risk_score=10,
        reason="low risk",
    )
    ledger.append(
        agent_id="agt_demo",
        action="export_data",
        target="customers",
        decision="block",
        risk_score=90,
        reason="high risk",
    )

    events = ledger.list_events()

    assert len(events) == 2
    assert events[0]["action"] == "export_data"
    assert events[0]["decision"] == "block"
    assert events[1]["action"] == "read_customer"
    assert ledger.verify_integrity() is True


def test_audit_ledger_restores_persisted_chain():
    store = MemoryAuditStore()
    first = AuditLedger(store=store)
    first.append("agt_demo", "echo", "demo", "allow", 1, "allowed")

    restored = AuditLedger(store=store)
    assert restored.count() == 1
    assert restored.verify_integrity() is True

    second = restored.append("agt_demo", "echo", "demo", "allow", 1, "allowed")
    assert second.previous_hash == store.events[0]["event_hash"]
    assert restored.verify_integrity() is True
