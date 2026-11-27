"""Session labels in Redis, shared by every worker and surviving restarts.

Why: with labels in process memory, a restart or a second worker saw a clean label for a session
that had already read private data and untrusted content: the flow rules failed open.

How:
- one Redis hash per session, fields `version` and `doc` (the label as JSON);
- every change is read -> apply the same label logic as the memory store -> write back with a
  Lua compare-and-set on `version`. If another worker wrote first, the write is refused and the
  change is re-applied to the newer label, so no worker's taint is ever lost;
- operator sessions expire after AGENTGUARD_FLOW_SESSION_TTL seconds without writes. An expired
  session no longer resolves, so it is blocked (rule F0): expiry fails closed. Default sessions do
  not expire;
- any Redis error becomes FlowStateUnavailable, which the gateway turns into a block.

Limit: if Redis loses data (flushed, no persistence), default labels come back clean. Run Redis
with persistence (AOF) for this store.
"""
from __future__ import annotations

from collections.abc import Callable
import json
import random
import time

from app.flow.session import (
    FlowStateUnavailable,
    LabelSource,
    SessionLabel,
    apply_private,
    apply_untrusted,
    apply_widen,
    default_session_id,
    new_session_id,
)

KEY_PREFIX = "agentguard:session:"
# Under contention every round has one winner; without backoff the same losers kept colliding and a
# writer gave up after 16 tries (seen with 8 threads on one session, 2026-11-27). Jittered
# exponential backoff spreads the retries out.
MAX_CAS_ATTEMPTS = 40
BACKOFF_BASE_SECONDS = 0.0005
BACKOFF_CAP_SECONDS = 0.05

# KEYS[1] label key; ARGV[1] expected version ("0" = must not exist); ARGV[2] new version;
# ARGV[3] document; ARGV[4] TTL in ms (0 = none). Returns 1 if written, 0 if someone else wrote first.
_CAS = """
local current = redis.call('HGET', KEYS[1], 'version')
if current == false then
  if ARGV[1] ~= '0' then return 0 end
elseif current ~= ARGV[1] then
  return 0
end
redis.call('HSET', KEYS[1], 'version', ARGV[2], 'doc', ARGV[3])
if tonumber(ARGV[4]) > 0 then redis.call('PEXPIRE', KEYS[1], ARGV[4]) end
return 1
"""


def _redis_errors() -> tuple[type[BaseException], ...]:
    try:
        from redis.exceptions import RedisError
    except ImportError:  # pragma: no cover - redis is a dependency; keep the store importable without it
        return (OSError,)
    return (RedisError, OSError)


class RedisSessionStore:
    def __init__(self, client, ttl_seconds: int = 86_400) -> None:
        self.redis = client
        self.ttl_ms = ttl_seconds * 1000
        self._errors = _redis_errors()

    @classmethod
    def from_url(cls, url: str, ttl_seconds: int = 86_400) -> "RedisSessionStore":
        import redis

        return cls(redis.Redis.from_url(url, decode_responses=True, socket_timeout=0.5), ttl_seconds)

    # --- low level -----------------------------------------------------------------------------

    def _call(self, *args):
        try:
            return self.redis.execute_command(*args)
        except self._errors as exc:
            raise FlowStateUnavailable(f"session store unavailable: {exc}") from exc

    def _load(self, session_id: str) -> SessionLabel | None:
        version, doc = self._call("HMGET", KEY_PREFIX + session_id, "version", "doc")
        if version is None or doc is None:
            return None
        return SessionLabel.from_dict(json.loads(doc))

    def _write(self, label: SessionLabel, expected: int) -> bool:
        ttl = 0 if label.session_id.startswith("default:") else self.ttl_ms
        label.version = expected + 1
        written = self._call("EVAL", _CAS, 1, KEY_PREFIX + label.session_id, str(expected), str(label.version),
                             json.dumps(label.to_dict()), str(ttl))
        return int(written) == 1

    def _update(self, session_id: str, change: Callable[[SessionLabel], object]):
        for attempt in range(MAX_CAS_ATTEMPTS):
            if attempt:
                time.sleep(random.uniform(0, min(BACKOFF_CAP_SECONDS, BACKOFF_BASE_SECONDS * 2 ** attempt)))
            current = self._load(session_id)
            if current is None:
                raise FlowStateUnavailable(f"session {session_id} disappeared while being updated")
            expected = current.version
            result = change(current)
            if self._write(current, expected):
                return current, result
        raise FlowStateUnavailable(f"session {session_id} is being updated too often to write safely")

    # --- the SessionStore interface ------------------------------------------------------------

    def create(self, agent_id: str, purpose: str = "") -> SessionLabel:
        label = SessionLabel(session_id=new_session_id(), agent_id=agent_id, purpose=purpose)
        if not self._write(label, expected=0):
            raise FlowStateUnavailable("session id collision")
        return label

    def get(self, session_id: str) -> SessionLabel | None:
        return self._load(session_id)

    def resolve(self, agent_id: str, session_id: str | None) -> SessionLabel | None:
        if session_id is None or session_id == default_session_id(agent_id):
            key = default_session_id(agent_id)
            label = self._load(key)
            if label is None:
                fresh = SessionLabel(session_id=key, agent_id=agent_id, purpose="default")
                if not self._write(fresh, expected=0):     # another worker created it first
                    label = self._load(key)
                else:
                    label = fresh
            return label
        label = self._load(session_id)
        if label is None or label.closed or label.agent_id != agent_id:
            return None
        return label

    def close(self, session_id: str) -> SessionLabel | None:
        if self._load(session_id) is None:
            return None
        if session_id.startswith("default:"):
            return self._load(session_id)

        def mark(label: SessionLabel):
            label.closed = True

        return self._update(session_id, mark)[0]

    def add_untrusted(self, label: SessionLabel, source: LabelSource) -> None:
        updated, _ = self._update(label.session_id, lambda current: apply_untrusted(current, source))
        label.untrusted_sources = updated.untrusted_sources

    def add_private(self, label: SessionLabel, source: LabelSource) -> None:
        updated, _ = self._update(label.session_id, lambda current: apply_private(current, source))
        label.private_sources = updated.private_sources

    def widen_private_readers(self, label: SessionLabel, event_id: str, extra: frozenset[str]) -> frozenset[str] | None:
        updated, widened = self._update(label.session_id, lambda current: apply_widen(current, event_id, extra))
        label.private_sources = updated.private_sources
        return widened

    def list(self) -> list[SessionLabel]:
        labels, cursor = [], 0
        while True:
            cursor, keys = self._call("SCAN", cursor, "MATCH", KEY_PREFIX + "*", "COUNT", 200)
            cursor = int(cursor)
            for key in keys:
                label = self._load(key.removeprefix(KEY_PREFIX))
                if label is not None:
                    labels.append(label)
            if cursor == 0:
                return labels

    def ping(self) -> bool:
        return self._call("PING") in (True, "PONG")
