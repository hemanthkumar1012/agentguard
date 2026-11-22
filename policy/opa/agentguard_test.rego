package agentguard

import rego.v1

# The OPA adapter supplies agent status/permissions, the base request context,
# detected data findings, and the result of scoped-credential validation.

test_unknown_agent_is_blocked if {
	result := data.agentguard.decision with input as {
		"agent": {"status": "revoked", "permissions": {}},
		"action": "read",
		"risk_score": 0,
		"data_classification": "public",
	}
	result == "block"
}

test_missing_permission_is_blocked if {
	result := data.agentguard.decision with input as {
		"agent": {"status": "active", "permissions": {}},
		"action": "delete",
		"risk_score": 0,
		"data_classification": "public",
	}
	result == "block"
}

test_sensitive_high_risk_requires_approval if {
	result := data.agentguard.decision with input as {
		"agent": {"status": "active", "permissions": {"read": true}},
		"action": "read",
		"risk_score": 65,
		"data_classification": "pii",
	}
	result == "require_approval"
}

test_sensitive_content_adds_risk if {
	result := data.agentguard.decision with input as {
		"agent": {"status": "active", "permissions": {"send_email": true}},
		"action": "send_email",
		"target": "external-mail",
		"risk_score": 45,
		"data_classification": "public",
		"data_findings": ["secret_marker"],
	}
	result == "require_approval"
}

test_invalid_scoped_credential_is_blocked if {
	result := data.agentguard.decision with input as {
		"agent": {"status": "active", "permissions": {"read": true}},
		"action": "read",
		"tool": "crm",
		"credential_valid": false,
		"risk_score": 0,
		"data_classification": "public",
	}
	result == "block"
}

test_high_risk_block_takes_precedence_over_approval if {
	result := data.agentguard.decision with input as {
		"agent": {"status": "active", "permissions": {"export_data": true}},
		"action": "export_data",
		"target": "external-storage",
		"risk_score": 60,
		"data_classification": "secret",
	}
	result == "block"
}

# Regression (2026-11-22): a non-sensitive request at risk 60-69 used to fall through to the
# default "block". It must be allowed, the same as the Python policy.
test_moderate_risk_non_sensitive_is_allowed if {
	result := data.agentguard.decision with input as {
		"agent": {"status": "active", "permissions": {"send_email": true}},
		"action": "send_email",
		"target": "https://mail.example.com",
		"risk_score": 65,
		"data_classification": "public",
	}
	result == "allow"
}

# Regression (2026-11-22): secrets found in the outbound data need human approval even at low risk.
test_outbound_findings_require_approval if {
	result := data.agentguard.decision with input as {
		"agent": {"status": "active", "permissions": {"send_email": true}},
		"action": "send_email",
		"target": "external-mail",
		"risk_score": 10,
		"data_classification": "public",
		"data_findings": ["api_key"],
	}
	result == "require_approval"
}
