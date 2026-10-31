package sentinelforge_test

import rego.v1

import data.sentinelforge

base := {
	"action": "order.read", "target": "orders", "environment": "development", "user_role": "customer",
	"tenant_id": "acmepay", "resource_tenant_id": "acmepay", "user_id": "cus_128", "resource_owner_id": "cus_128",
	"args": {}, "has_findings": false, "injection_detected": false, "target_external": false,
}

with_fields(overrides) := object.union(base, overrides)

test_own_order_read_allowed if {
	sentinelforge.decision == "allow" with input as base
}

test_large_refund_requires_approval if {
	sentinelforge.decision == "require_approval" with input as with_fields({"action": "refund.issue", "args": {"order_id": "ORD-1077", "amount": 18000}})
}

test_hard_cap_beats_approval if {
	sentinelforge.decision == "block" with input as with_fields({"action": "refund.issue", "args": {"order_id": "ORD-2002", "amount": 250000}})
	"refund-above-threshold" in sentinelforge.matched_policies with input as with_fields({"action": "refund.issue", "args": {"order_id": "ORD-2002", "amount": 250000}})
}

test_refund_without_order_denied if {
	sentinelforge.decision == "block" with input as with_fields({"action": "refund.issue", "args": {"amount": 900}})
}

test_small_refund_allowed if {
	sentinelforge.decision == "allow" with input as with_fields({"action": "refund.issue", "args": {"order_id": "ORD-1042", "amount": 900}})
}

test_non_numeric_amount_ignored if {
	sentinelforge.decision == "allow" with input as with_fields({"action": "refund.issue", "args": {"order_id": "ORD-1042", "amount": "18000"}})
}

test_cross_customer_denied_for_customer if {
	sentinelforge.decision == "block" with input as with_fields({"resource_owner_id": "cus_204"})
}

test_cross_customer_allowed_for_manager if {
	sentinelforge.decision == "allow" with input as with_fields({"resource_owner_id": "cus_204", "user_role": "support_manager"})
}

test_cross_tenant_denied_even_for_admin if {
	sentinelforge.decision == "block" with input as with_fields({"resource_tenant_id": "zenbank", "user_role": "admin"})
}

test_injection_blocks_privileged_action if {
	sentinelforge.decision == "block" with input as with_fields({"action": "email.send", "target": "attacker@evil.example", "injection_detected": true, "target_external": true})
}

test_external_email_requires_approval if {
	sentinelforge.decision == "require_approval" with input as with_fields({"action": "email.send", "target_external": true, "has_findings": true})
}

test_outbound_pii_redacted if {
	sentinelforge.decision == "allow_with_redaction" with input as with_fields({"action": "ticket.create", "has_findings": true})
}

test_production_write_escalates if {
	sentinelforge.decision == "escalate_to_human" with input as with_fields({"action": "db.write", "environment": "production"})
}

test_export_denied_for_customer_and_approval_for_compliance if {
	sentinelforge.decision == "block" with input as with_fields({"action": "customers.export"})
	sentinelforge.decision == "require_approval" with input as with_fields({"action": "customers.export", "user_role": "compliance_officer"})
}

test_elevated_session_requires_approval_for_privileged_action if {
	sentinelforge.decision == "require_approval" with input as with_fields({"action": "email.send", "session_risk": 75})
	sentinelforge.decision == "allow" with input as with_fields({"action": "order.read", "session_risk": 75})
}
