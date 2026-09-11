from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4


class AgentStatus(str, Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"


@dataclass(frozen=True)
class AgentIdentity:
    agent_id: str
    name: str
    owner: str
    environment: str
    permissions: frozenset[str] = field(default_factory=frozenset)
    status: AgentStatus = AgentStatus.ACTIVE
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class AgentRegistry:
    """Small in-memory registry used by the first vertical slice.

    The interface is intentionally storage-agnostic so it can be backed by
    PostgreSQL/Supabase without changing the policy layer later.
    """

    def __init__(self) -> None:
        self._agents: dict[str, AgentIdentity] = {}

    def register(
        self,
        name: str,
        owner: str,
        environment: str = "development",
        permissions: set[str] | None = None,
    ) -> AgentIdentity:
        agent = AgentIdentity(
            agent_id=f"agt_{uuid4().hex[:16]}",
            name=name,
            owner=owner,
            environment=environment,
            permissions=frozenset(permissions or set()),
        )
        self._agents[agent.agent_id] = agent
        return agent

    def get(self, agent_id: str) -> AgentIdentity | None:
        return self._agents.get(agent_id)

    def suspend(self, agent_id: str) -> AgentIdentity:
        agent = self._agents[agent_id]
        updated = AgentIdentity(**{**agent.__dict__, "status": AgentStatus.SUSPENDED})
        self._agents[agent_id] = updated
        return updated

    def revoke(self, agent_id: str) -> AgentIdentity:
        agent = self._agents[agent_id]
        updated = AgentIdentity(**{**agent.__dict__, "status": AgentStatus.REVOKED})
        self._agents[agent_id] = updated
        return updated
