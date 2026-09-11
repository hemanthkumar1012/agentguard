from dataclasses import dataclass

from app.identity import AgentRegistry, AgentStatus


@dataclass(frozen=True)
class DelegationDecision:
    allowed: bool
    reason: str


class AgentAuthorization:
    """Authorize one agent acting on behalf of another using explicit scopes."""

    def __init__(self, registry: AgentRegistry) -> None:
        self.registry = registry
        self._delegations: dict[tuple[str, str], frozenset[str]] = {}

    def grant(self, source_agent_id: str, target_agent_id: str, scopes: set[str]) -> None:
        source = self.registry.get(source_agent_id)
        target = self.registry.get(target_agent_id)
        if source is None or target is None:
            raise KeyError("Both source and target agents must exist")
        if source.status != AgentStatus.ACTIVE or target.status != AgentStatus.ACTIVE:
            raise ValueError("Both agents must be active")
        if not scopes.issubset(source.permissions):
            raise PermissionError("Delegated scopes exceed source agent permissions")
        self._delegations[(source_agent_id, target_agent_id)] = frozenset(scopes)

    def check(self, source_agent_id: str, target_agent_id: str, action: str) -> DelegationDecision:
        source = self.registry.get(source_agent_id)
        target = self.registry.get(target_agent_id)
        if source is None or target is None:
            return DelegationDecision(False, "Source or target agent does not exist")
        if source.status != AgentStatus.ACTIVE or target.status != AgentStatus.ACTIVE:
            return DelegationDecision(False, "Source or target agent is not active")
        if action not in target.permissions:
            return DelegationDecision(False, "Target agent does not permit the delegated action")
        scopes = self._delegations.get((source_agent_id, target_agent_id), frozenset())
        if action not in scopes:
            return DelegationDecision(False, "No delegation exists for the requested action")
        return DelegationDecision(True, "Delegation is explicitly authorized")
