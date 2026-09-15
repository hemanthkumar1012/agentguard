from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
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
    def __init__(self, default_ttl_seconds: int = 300, store=None) -> None:
        self.default_ttl_seconds = default_ttl_seconds
        self.store = store
        self._credentials: dict[str, ScopedCredential] = {}

    @staticmethod
    def _hash(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def issue(
        self,
        agent_id: str,
        tool: str,
        scopes: set[str],
        ttl_seconds: int | None = None,
    ) -> ScopedCredential:
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

        if self.store is not None:
            self.store.insert_credential(
                credential_id=credential.credential_id,
                agent_id=credential.agent_id,
                tool=credential.tool,
                scopes=credential.scopes,
                token_hash=self._hash(credential.token),
                expires_at=credential.expires_at,
            )

        return credential

    def validate(
        self,
        credential_id: str,
        agent_id: str,
        tool: str,
        required_scope: str,
        token: str | None = None,
    ) -> bool:
        credential = self._credentials.get(credential_id)
        if credential is not None:
            return self._matches(credential, agent_id, tool, required_scope, token)

        if self.store is None or token is None:
            return False

        row = self.store.get_credential(credential_id)
        if row is None:
            return False
        if row["agent_id"] != agent_id or row["tool"] != tool:
            return False

        expires_at = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
        if expires_at <= datetime.now(timezone.utc) or row.get("revoked_at"):
            return False

        return required_scope in set(row.get("scopes", [])) and hmac.compare_digest(
            self._hash(token), row["token_hash"]
        )

    def _matches(
        self,
        credential: ScopedCredential,
        agent_id: str,
        tool: str,
        required_scope: str,
        token: str | None,
    ) -> bool:
        if credential.agent_id != agent_id or credential.tool != tool:
            return False
        if credential.expires_at <= datetime.now(timezone.utc):
            return False
        if token is None or not hmac.compare_digest(self._hash(token), self._hash(credential.token)):
            return False
        return required_scope in credential.scopes

    def revoke(self, credential_id: str) -> bool:
        removed = self._credentials.pop(credential_id, None) is not None
        if self.store is not None:
            removed = self.store.revoke_credential(credential_id) or removed
        return removed

    def list_metadata(self) -> list[dict]:
        if self.store is not None and hasattr(self.store, "list_credentials"):
            return self.store.list_credentials()
        return [
            {
                "credential_id": credential.credential_id,
                "agent_id": credential.agent_id,
                "tool": credential.tool,
                "scopes": sorted(credential.scopes),
                "expires_at": credential.expires_at,
                "revoked": False,
            }
            for credential in self._credentials.values()
        ]
