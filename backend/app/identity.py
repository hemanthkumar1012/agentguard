from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import uuid4


class AgentStatus(str):
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
    status: str = AgentStatus.ACTIVE
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class AgentRegistry:
    def __init__(self, store=None) -> None:
        self._agents: dict[str, AgentIdentity] = {}
        self.store = store
        if self.store is not None:
            self._load_persisted()

    def _load_persisted(self) -> None:
        for row in self.store.list_agents():
            created_at = row.get("created_at")
            if isinstance(created_at, str):
                created_at = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
            self._agents[row["agent_id"]] = AgentIdentity(
                agent_id=row["agent_id"],
                name=row["name"],
                owner=row["owner"],
                environment=row.get("environment", "development"),
                permissions=frozenset(row.get("permissions", [])),
                status=row.get("status", AgentStatus.ACTIVE),
                created_at=created_at or datetime.now(timezone.utc),
            )

    def register(self, name, owner, environment="development", permissions=None):
        agent = AgentIdentity(
            agent_id=f"agt_{uuid4().hex[:16]}",
            name=name,
            owner=owner,
            environment=environment,
            permissions=frozenset(permissions or set()),
        )
        if self.store is not None:
            self.store.insert_agent(agent)
        self._agents[agent.agent_id] = agent
        return agent

    def get(self, agent_id):
        return self._agents.get(agent_id)

    def list_agents(self) -> list[AgentIdentity]:
        return list(self._agents.values())

    def suspend(self, agent_id):
        agent = self._agents[agent_id]
        updated = AgentIdentity(**{**agent.__dict__, "status": AgentStatus.SUSPENDED})
        if self.store is not None:
            self.store.update_agent_status(agent_id, AgentStatus.SUSPENDED)
        self._agents[agent_id] = updated
        return updated

    def revoke(self, agent_id):
        agent = self._agents[agent_id]
        updated = AgentIdentity(**{**agent.__dict__, "status": AgentStatus.REVOKED})
        if self.store is not None:
            self.store.update_agent_status(agent_id, AgentStatus.REVOKED)
        self._agents[agent_id] = updated
        return updated
