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
    def __init__(self) -> None:
        self._agents: dict[str, AgentIdentity] = {}

    def register(self, name, owner, environment="development", permissions=None):
        agent = AgentIdentity(
            agent_id=f"agt_{uuid4().hex[:16]}",
            name=name,
            owner=owner,
            environment=environment,
            permissions=frozenset(permissions or set()),
        )
        self._agents[agent.agent_id] = agent
        return agent

    def get(self, agent_id):
        return self._agents.get(agent_id)

    def list_agents(self) -> list[AgentIdentity]:
        return list(self._agents.values())

    def suspend(self, agent_id):
        agent = self._agents[agent_id]
        updated = AgentIdentity(**{**agent.__dict__, "status": AgentStatus.SUSPENDED})
        self._agents[agent_id] = updated
        return updated

    def revoke(self, agent_id):
        agent = self._agents[agent_id]
        updated = AgentIdentity(**{**agent.__dict__, "status": AgentStatus.REVOKED})
        self._agents[agent_id] = updated
        return updated
