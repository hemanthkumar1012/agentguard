from app.audit import AuditLedger


def test_audit_events_are_hash_chained() -> None:
    ledger = AuditLedger()

    first = ledger.append(
        agent_id="agt_test",
        action="read",
        target="crm",
        decision="allow",
        risk_score=10,
        reason="permitted",
    )
    second = ledger.append(
        agent_id="agt_test",
        action="export_data",
        target="crm",
        decision="require_approval",
        risk_score=70,
        reason="approval required",
    )

    assert first.previous_hash == "GENESIS"
    assert second.previous_hash == first.event_hash
    assert first.event_hash
    assert second.event_hash
    assert ledger.verify_integrity() is True


def test_audit_integrity_detects_tampering() -> None:
    ledger = AuditLedger()
    ledger.append(
        agent_id="agt_test",
        action="read",
        target="crm",
        decision="allow",
        risk_score=10,
        reason="permitted",
    )

    event = ledger._events[0]
    ledger._events[0] = event.__class__(
        **{**event.__dict__, "reason": "tampered"}
    )

    assert ledger.verify_integrity() is False
