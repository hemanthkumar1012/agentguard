package agentguard

import rego.v1

# Basic policy regression tests for the OPA adapter.

test_unknown_agent_is_blocked if {
  decision with input as {
    "agent": {"status": "revoked", "permissions": {}},
    "action": "read",
    "risk_score": 0,
    "data_classification": "public"
  }
  decision == "block"
}

test_sensitive_high_risk_requires_approval if {
  decision with input as {
    "agent": {"status": "active", "permissions": {"read": true}},
    "action": "read",
    "risk_score": 65,
    "data_classification": "pii"
  }
  decision == "require_approval"
}
