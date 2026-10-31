package sentinelforge

# Rego mirror of policy/rules/fintech_support.yaml for teams that run OPA as a
# sidecar. The Python engine is authoritative in the API; parity is enforced by
# sentinelforge_test.rego (same cases as backend/tests/test_policy_engine.py).
#
# Input shape (built by the gateway after identity, credential and inspection):
#   {
#     "action": "refund.issue", "target": "payments", "environment": "production",
#     "user_role": "customer", "tenant_id": "acmepay", "resource_tenant_id": "acmepay",
#     "user_id": "cus_128", "resource_owner_id": "cus_128",
#     "args": {"order_id": "ORD-1077", "amount": 18000},
#     "has_findings": false, "injection_detected": false, "target_external": false,
#     "session_risk": 0
#   }

import rego.v1

privileged_actions := {"email.send", "customers.export", "refund.issue", "subscription.cancel", "db.write", "permissions.change"}

precedence := {
	"block": 6,
	"escalate_to_human": 5,
	"require_approval": 4,
	"allow_with_redaction": 3,
	"allow": 1,
}

amount := input.args.amount if is_number(input.args.amount)

tenant_mismatch if {
	input.tenant_id
	input.resource_tenant_id
	input.tenant_id != input.resource_tenant_id
}

owner_mismatch if {
	input.user_id
	input.resource_owner_id
	input.user_id != input.resource_owner_id
}

order_missing if object.get(input.args, "order_id", null) == null

# ---------------------------------------------------------------- rules
matches contains {"id": "cross-tenant-access", "decision": "block"} if tenant_mismatch

matches contains {"id": "cross-customer-data-access", "decision": "block"} if {
	owner_mismatch
	not input.user_role in {"admin", "support_manager"}
}

matches contains {"id": "injected-instruction-privileged-action", "decision": "block"} if {
	input.injection_detected == true
	input.action in privileged_actions
}

matches contains {"id": "bulk-export-denied", "decision": "block"} if {
	input.action == "customers.export"
	not input.user_role in {"admin", "compliance_officer"}
}

matches contains {"id": "bulk-export-approval", "decision": "require_approval"} if {
	input.action == "customers.export"
	input.user_role in {"admin", "compliance_officer"}
}

matches contains {"id": "refund-requires-order", "decision": "block"} if {
	input.action in {"refund.issue", "refund.request"}
	order_missing
}

matches contains {"id": "refund-hard-cap", "decision": "block"} if {
	input.action == "refund.issue"
	amount > 100000
}

matches contains {"id": "refund-above-threshold", "decision": "require_approval"} if {
	input.action == "refund.issue"
	amount > 5000
}

matches contains {"id": "subscription-cancel-approval", "decision": "require_approval"} if {
	input.action == "subscription.cancel"
}

matches contains {"id": "external-email-approval", "decision": "require_approval"} if {
	input.action == "email.send"
	input.target_external == true
}

matches contains {"id": "production-write-escalation", "decision": "escalate_to_human"} if {
	input.environment == "production"
	input.action in {"db.write", "permissions.change"}
}

matches contains {"id": "elevated-session-privileged-approval", "decision": "require_approval"} if {
	object.get(input, "session_risk", 0) >= 60
	input.action in privileged_actions
}

matches contains {"id": "outbound-pii-redaction", "decision": "allow_with_redaction"} if {
	input.action in {"email.send", "ticket.create"}
	input.has_findings == true
}

# ---------------------------------------------------------------- outcome
# Strictest matching decision wins; no match means "allow" (the gateway's
# baseline risk policy still applies on top, as in the Python engine).
strictest := max({precedence[m.decision] | some m in matches})

default decision := "allow"

decision := d if {
	count(matches) > 0
	some d, rank in precedence
	rank == strictest
}

matched_policies := sort([m.id | some m in matches])
