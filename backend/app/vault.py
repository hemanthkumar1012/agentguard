"""Credential injection: the agent works with handles, the gateway holds the real secrets.

Before, an agent that needed an API key read it from a vault tool, so the key sat in its context. A
prompt injection could then send it anywhere, and even a legitimate call made the inspector see "a
secret leaving" (trace api-key-used-with-its-own-provider needed a human every time).

Now:
- an operator stores the secret with the destinations it may be sent to and the agents that may use it;
- the agent writes a handle such as `{{secret:razorpay}}` wherever the key belongs (a header, a URL);
- the gateway checks every handle in an allowed request: the secret exists, this agent may use it, and
  every destination of the call matches the secret's allowed destinations. If not, the request is
  blocked (rule S1). This check happens before policy, so nothing else can allow it;
- only after the decision, at execution, is the handle replaced by the real value;
- the tool's output is scrubbed before the agent sees it: the real value, and its base64, hex and
  URL-encoded forms, become the handle again (an API that echoes the key back cannot leak it).

So the decision path, the audit trail and the agent's context never contain the secret, and a fully
hijacked agent cannot leak a key it never had. Values are kept in process memory here; a production
deployment would load them from a KMS or secrets manager.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import datetime, timezone
from fnmatch import fnmatchcase
import hashlib
import re
from threading import Lock
from urllib.parse import quote

HANDLE = re.compile(r"\{\{\s*secret:([A-Za-z0-9_.-]{1,64})\s*\}\}")
NAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


@dataclass(frozen=True)
class StoredSecret:
    name: str
    value: str = field(repr=False)
    allowed_destinations: tuple[str, ...]
    allowed_agents: tuple[str, ...]          # "*" = any agent
    created_at: datetime

    def metadata(self) -> dict:
        return {
            "name": self.name,
            "allowed_destinations": list(self.allowed_destinations),
            "allowed_agents": list(self.allowed_agents),
            "created_at": self.created_at.isoformat(),
            # enough to tell two versions apart, never enough to recover the value
            "sha256_prefix": hashlib.sha256(self.value.encode()).hexdigest()[:12],
        }


def handles_in(value) -> set[str]:
    """Names of every {{secret:...}} handle anywhere in a JSON-like value."""
    found: set[str] = set()

    def walk(item, depth=0):
        if depth > 10:
            return
        if isinstance(item, str):
            found.update(HANDLE.findall(item))
        elif isinstance(item, dict):
            for key, inner in item.items():
                walk(key, depth + 1)
                walk(inner, depth + 1)
        elif isinstance(item, (list, tuple)):
            for inner in item:
                walk(inner, depth + 1)

    walk(value)
    return found


def _map_strings(value, change, depth=0):
    if depth > 10:
        return value
    if isinstance(value, str):
        return change(value)
    if isinstance(value, dict):
        return {key: _map_strings(inner, change, depth + 1) for key, inner in value.items()}
    if isinstance(value, list):
        return [_map_strings(inner, change, depth + 1) for inner in value]
    if isinstance(value, tuple):
        return tuple(_map_strings(inner, change, depth + 1) for inner in value)
    return value


class SecretVault:
    def __init__(self) -> None:
        self._secrets: dict[str, StoredSecret] = {}
        self._lock = Lock()

    def put(self, name: str, value: str, allowed_destinations: list[str], allowed_agents: list[str]) -> StoredSecret:
        if not NAME.match(name):
            raise ValueError("secret names use letters, digits, '.', '_' or '-' (max 64)")
        if len(value) < 8:
            raise ValueError("secret value is too short to be a credential")
        if not allowed_destinations or any(p.strip() in {"*", "*://*", "http*"} for p in allowed_destinations):
            raise ValueError("a secret must be bound to specific destinations, not to everything")
        if not allowed_agents:
            raise ValueError("name the agents that may use this secret, or '*'")
        secret = StoredSecret(name, value, tuple(p.strip().lower() for p in allowed_destinations),
                              tuple(allowed_agents), datetime.now(timezone.utc))
        with self._lock:
            self._secrets[name] = secret
        return secret

    def revoke(self, name: str) -> bool:
        with self._lock:
            return self._secrets.pop(name, None) is not None

    def list(self) -> list[dict]:
        return [s.metadata() for s in sorted(self._secrets.values(), key=lambda s: s.name)]

    def check(self, agent_id: str, payload, extra_text: list[str], destinations: list[str]) -> str | None:
        """None if every handle in the request may be used here, otherwise the reason to block."""
        names = handles_in(payload) | handles_in(extra_text)
        for name in sorted(names):
            secret = self._secrets.get(name)
            if secret is None:
                return f"Secret handle '{name}' does not exist or was revoked."
            if "*" not in secret.allowed_agents and agent_id not in secret.allowed_agents:
                return f"This agent may not use secret '{name}'."
            for destination in destinations:
                if not any(fnmatchcase(destination.strip().lower(), pattern) for pattern in secret.allowed_destinations):
                    return (f"Secret '{name}' may only be sent to {', '.join(secret.allowed_destinations)}; "
                            f"this request goes to {destination}.")
        return None

    def inject(self, payload):
        """Replaces handles with real values. Call only for an allowed request, right before execution."""
        def replace(text: str) -> str:
            return HANDLE.sub(lambda m: self._secrets[m.group(1)].value if m.group(1) in self._secrets else m.group(0), text)
        return _map_strings(payload, replace)

    def scrub(self, output):
        """Turns any copy of a stored secret in tool output back into its handle."""
        forms: list[tuple[str, str]] = []
        for secret in self._secrets.values():
            raw = secret.value.encode()
            handle = "{{secret:%s}}" % secret.name
            for form in {secret.value, base64.b64encode(raw).decode(), base64.b64encode(raw).decode().rstrip("="),
                         base64.urlsafe_b64encode(raw).decode().rstrip("="), raw.hex(), quote(secret.value, safe="")}:
                forms.append((form, handle))
        forms.sort(key=lambda pair: len(pair[0]), reverse=True)   # longest first, so encodings win over substrings

        def replace(text: str) -> str:
            for form, handle in forms:
                if form and form in text:
                    text = text.replace(form, handle)
            return text
        return _map_strings(output, replace)
