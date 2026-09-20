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
