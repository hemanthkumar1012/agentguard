from app.audit import AuditLedger


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
