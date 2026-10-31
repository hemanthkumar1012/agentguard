from enum import Enum

from pydantic import BaseModel, Field


class Decision(str, Enum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    BLOCK = "block"
    ALLOW_WITH_REDACTION = "allow_with_redaction"
    RATE_LIMIT = "rate_limit"
    ESCALATE_TO_HUMAN = "escalate_to_human"

    @property
    def is_executable(self) -> bool:
        """Decisions after which the tool may run (with a redacted payload for redaction)."""
        return self in {Decision.ALLOW, Decision.ALLOW_WITH_REDACTION}

    @property
    def needs_human(self) -> bool:
        return self in {Decision.REQUIRE_APPROVAL, Decision.ESCALATE_TO_HUMAN}


# Where the text in `content` came from. Anything other than the authenticated
# user's own message is untrusted data and is scanned for injected instructions.
CONTENT_SOURCES = {
    "user",
    "retrieved_document",
    "tool_output",
    "email",
    "pdf",
    "webpage",
    "database_field",
    "agent",
}


class ActionRequest(BaseModel):
    agent_id: str = Field(min_length=1)
    action: str = Field(min_length=1)
    target: str = Field(min_length=1)
    data_classification: str = Field(default="public", min_length=1)
    risk_score: float = Field(default=0, ge=0, le=100)
    content: str | None = Field(default=None, max_length=100_000)
    content_source: str = Field(default="user", min_length=1, max_length=50)
    tool: str | None = Field(default=None, min_length=1, max_length=100)
    credential_id: str | None = Field(default=None, min_length=1, max_length=200)
    credential_token: str | None = Field(default=None, min_length=1, max_length=500)
    correlation_id: str | None = Field(default=None, min_length=1, max_length=100)
    approval_id: str | None = Field(default=None, min_length=1, max_length=100)
    execution_payload: dict = Field(default_factory=dict)
    # Context used by the declarative policy engine. All optional so that the
    # original request shape keeps working unchanged.
    tenant_id: str | None = Field(default=None, min_length=1, max_length=100)
    user_id: str | None = Field(default=None, min_length=1, max_length=100)
    user_role: str | None = Field(default=None, min_length=1, max_length=50)
    resource_owner_id: str | None = Field(default=None, min_length=1, max_length=100)
    resource_tenant_id: str | None = Field(default=None, min_length=1, max_length=100)
    environment: str | None = Field(default=None, min_length=1, max_length=50)


class DecisionResponse(BaseModel):
    decision: Decision
    reason: str
    agent_id: str
    action: str
    target: str
    risk_score: float
    risk_factors: list[str] = Field(default_factory=list)
    data_findings: list[str] = Field(default_factory=list)
    approval_id: str | None = None
    policy_id: str | None = None
    matched_policies: list[str] = Field(default_factory=list)
    approver_role: str | None = None
    retry_after_seconds: int | None = None
    redacted_content: str | None = None
    redacted_payload: dict | None = None
