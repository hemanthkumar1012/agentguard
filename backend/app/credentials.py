from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from secrets import token_urlsafe


@dataclass(frozen=True)
class ScopedCredential:
    credential_id: str
    agent_id: str
    tool: str
    scopes: frozenset[str]
    token: str
    expires_at: datetime


class CredentialBroker:
    """Issues opaque, short-lived, least-privilege credentials for demos/tests."""

    def __init__(self, default_ttl_seconds: int = 300) -> None:
        self.default_ttl_seconds = default_ttl_seconds
        self._credentials: dict[str, ScopedCredential] = {}

    def issue(self, agent_id: str, tool: str, scopes: set[str], ttl_seconds: int | None = None) -> ScopedCredential:
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl_seconds
        if ttl <= 0:
            raise ValueError("Credential TTL must be positive")
        credential = ScopedCredential(
            credential_id=f"cred_{token_urlsafe(10)}",
            agent_id=agent_id,
            tool=tool,
            scopes=frozenset(scopes),
            token=token_urlsafe(32),
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=ttl),
        )
        self._credentials[credential.credential_id] = credential
        return credential

    def validate(self, credential_id: str, agent_id: str, tool: str, required_scope: str) -> bool:
        credential = self._credentials.get(credential_id)
        if credential is None or credential.agent_id != agent_id or credential.tool != tool:
            return False
        if credential.expires_at <= datetime.now(timezone.utc):
            return False
        return required_scope in credential.scopes

    def revoke(self, credential_id: str) -> bool:
        return self._credentials.pop(credential_id, None) is not None
