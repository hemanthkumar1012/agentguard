package agentguard

default decision := "allow"

high_risk_actions := {"delete", "transfer_funds", "export_data", "rotate_credentials"}
sensitive_data := {"pii", "financial", "credentials", "secret"}

decision := "block" if {
  input.agent.status != "active"
}

decision := "block" if {
  not input.agent.permissions[input.action]
}

decision := "block" if {
  input.action in high_risk_actions
  input.risk_score >= 80
}

decision := "require_approval" if {
  input.data_classification in sensitive_data
  input.risk_score >= 60
}

decision := "require_approval" if {
  input.risk_score >= 70
}

reason := "Request satisfies AgentGuard runtime policy." if { decision == "allow" }
reason := "Agent identity or action permission is not valid." if { decision == "block" }
reason := "Current risk requires human approval." if { decision == "require_approval" }
