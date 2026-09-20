package agentguard

import rego.v1

default decision := "block"
default reason := "Agent identity or action permission is not valid."

default credential_valid := true

default data_findings := []
default base_risk_score := 0

default data_classification := "public"
default target := ""
default action := ""

# The adapter may pass credential_valid=false after validating a scoped
# credential. Requests without a tool do not need credential validation.
credential_valid := input.credential_valid if {
    object.get(input, "credential_valid", true) == false
}

base_risk_score := input.risk_score if {
    is_number(input.risk_score)
}

data_classification := input.data_classification if {
    is_string(input.data_classification)
}

target := input.target if {
    is_string(input.target)
}

action := input.action if {
    is_string(input.action)
}

data_findings := input.data_findings if {
    is_array(input.data_findings)
}

high_risk_actions := {"delete", "transfer_funds", "export_data", "rotate_credentials"}
sensitive_data := {"pii", "financial", "credentials", "secret"}

agent_is_active if {
    input.agent.status == "active"
}

agent_has_permission if {
    input.agent.permissions[action]
}

credential_required if {
    object.get(input, "tool", null) != null
}

credential_is_valid if {
    not credential_required
}

credential_is_valid if {
    credential_required
    credential_valid
}

sensitive_classification if {
    data_classification in sensitive_data
}

high_impact_action if {
    action in high_risk_actions
}

unencrypted_target if {
    startswith(target, "http://")
}

external_target if {
    contains(lower(target), "external")
}

sensitive_risk := 15 if {
    sensitive_classification
}

sensitive_risk := 0 if {
    not sensitive_classification
}

high_impact_risk := 20 if {
    high_impact_action
}

high_impact_risk := 0 if {
    not high_impact_action
}

transport_risk := 10 if {
    unencrypted_target
}

transport_risk := 0 if {
    not unencrypted_target
}

external_risk := 10 if {
    external_target
}

external_risk := 0 if {
    not external_target
}

content_risk := 20 if {
    count(data_findings) > 0
}

content_risk := 0 if {
    count(data_findings) == 0
}

contextual_risk_score := min([100, base_risk_score + sensitive_risk + high_impact_risk + transport_risk + external_risk + content_risk])

identity_or_permission_invalid if {
    not agent_is_active
}

identity_or_permission_invalid if {
    not agent_has_permission
}

credential_invalid if {
    not credential_is_valid
}

blocked if {
    identity_or_permission_invalid
}

blocked if {
    credential_invalid
}

blocked if {
    high_impact_action
    contextual_risk_score >= 80
}

sensitive_approval_required if {
    sensitive_classification
    contextual_risk_score >= 60
}

decision := "block" if {
    blocked
}

reason := "Scoped credential is invalid, expired, revoked, or insufficient." if {
    not identity_or_permission_invalid
    credential_invalid
}

reason := "High-risk action exceeds the runtime risk threshold." if {
    not identity_or_permission_invalid
    not credential_invalid
    high_impact_action
    contextual_risk_score >= 80
}

decision := "require_approval" if {
    not blocked
    sensitive_classification
    contextual_risk_score >= 60
}

decision := "require_approval" if {
    not blocked
    contextual_risk_score >= 70
}

reason := "Sensitive data access requires human approval at this risk level." if {
    not blocked
    sensitive_classification
    contextual_risk_score >= 60
}

reason := "Risk score requires human approval before execution." if {
    not blocked
    not sensitive_approval_required
    contextual_risk_score >= 70
}

decision := "allow" if {
    not blocked
    contextual_risk_score < 60
}

reason := "Request satisfies the initial runtime policy." if {
    decision == "allow"
}
