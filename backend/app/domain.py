from enum import Enum

from pydantic import BaseModel, Field


class Decision(str, Enum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    BLOCK = "block"


class ActionRequest(BaseModel):
    agent_id: str = Field(min_length=1)
    action: str = Field(min_length=1)
    target: str = Field(min_length=1)
    data_classification: str = Field(default="public", min_length=1)
    risk_score: float = Field(default=0, ge=0, le=100)
    content: str | None = Field(default=None, max_length=100_000)
    tool: str | None = Field(default=None, min_length=1, max_length=100)
    credential_id: str | None = Field(default=None, min_length=1, max_length=200)
    correlation_id: str | None = Field(default=None, min_length=1, max_length=100)


class DecisionResponse(BaseModel):
    decision: Decision
    reason: str
    agent_id: str
    action: str
    target: str
    risk_score: float
    risk_factors: list[str] = Field(default_factory=list)
    data_findings: list[str] = Field(default_factory=list)
