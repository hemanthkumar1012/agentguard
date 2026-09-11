package agentguard.runtime

# Policy-as-code reference implementation.
# The FastAPI policy engine remains the local fallback; this Rego policy
# defines the same security contract for deployments running OPA.

default decision := "allow"

decision := "block" if {
    input.agent_status != "active"
}

decision := "block" if {
    not input.permission_granted
}

decision := "block" if {
    input.action in {"delete", "transfer_funds", "export_data", "rotate_credentials"}
    input.risk_score >= 80
}

decision := "require_approval" if {
    input.data_classification in {"pii", "financial", "credentials", "secret"}
    input.risk_score >= 60
}

decision := "require_approval" if {
    input.risk_score >= 70
}
