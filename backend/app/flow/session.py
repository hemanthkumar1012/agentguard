"""Per-session labels: what an agent has touched so far, worked out by AgentGuard, not the agent.

A session starts clean. Each allowed tool call can add to its label:

- reading untrusted content (a web page, an inbound email, a public issue) marks it *untrusted*;
- reading private data adds a source whose readers the session must respect from then on.

Labels only grow. An agent cannot clean its own label: sessions are created by an operator (or
the orchestrator holding operator credentials), and a request without a session falls into the
agent's long-lived default session rather than a fresh one.

Two stores share the same label logic (the `apply_*` functions below):
MemorySessionStore for one process, RedisSessionStore (app/flow/redis_store.py) for several
workers and restarts.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from threading import Lock
from uuid import uuid4

from app.flow.labels import meet

# A long-lived default session would otherwise keep one entry per call forever.
MAX_SOURCES_PER_LABEL = 100


class FlowStateUnavailable(Exception):
    """The label store could not be read or written. Callers must fail closed."""


@dataclass(frozen=True)
class LabelSource:
    event_id: str
    tool: str
    action: str
    readers: frozenset[str] = frozenset()

    def to_dict(self) -> dict:
        return {"event_id": self.event_id, "tool": self.tool, "action": self.action, "readers": sorted(self.readers)}

    @classmethod
    def from_dict(cls, data: dict) -> "LabelSource":
        return cls(data["event_id"], data["tool"], data["action"], frozenset(data.get("readers") or []))


@dataclass
class SessionLabel:
    session_id: str
    agent_id: str
    purpose: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    untrusted_sources: list[LabelSource] = field(default_factory=list)
    private_sources: list[LabelSource] = field(default_factory=list)
    closed: bool = False
    version: int = 0          # bumped on every write; the Redis store uses it for compare-and-set

    @property
    def untrusted(self) -> bool:
        return bool(self.untrusted_sources)

    @property
    def holds_private(self) -> bool:
        return bool(self.private_sources)

    @property
    def readers(self) -> frozenset[str] | None:
        """Principals allowed to read everything this session has read; None if it read nothing private."""
        result: frozenset[str] | None = None
        for source in self.private_sources:
            result = meet(result, source.readers)
        return result

    def summary(self) -> dict:
        readers = self.readers
        return {
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "purpose": self.purpose,
            "created_at": self.created_at.isoformat(),
            "closed": self.closed,
            "untrusted": self.untrusted,
            "holds_private": self.holds_private,
            "readers": None if readers is None else sorted(readers),
            "untrusted_sources": [s.to_dict() for s in self.untrusted_sources],
            "private_sources": [s.to_dict() for s in self.private_sources],
        }

    def to_dict(self) -> dict:
        return {**self.summary(), "version": self.version}

    @classmethod
    def from_dict(cls, data: dict) -> "SessionLabel":
        return cls(
            session_id=data["session_id"],
            agent_id=data["agent_id"],
            purpose=data.get("purpose", ""),
            created_at=datetime.fromisoformat(data["created_at"]),
            untrusted_sources=[LabelSource.from_dict(s) for s in data.get("untrusted_sources", [])],
            private_sources=[LabelSource.from_dict(s) for s in data.get("private_sources", [])],
            closed=bool(data.get("closed")),
            version=int(data.get("version", 0)),
        )


def default_session_id(agent_id: str) -> str:
    return f"default:{agent_id}"


def new_session_id() -> str:
    return f"ses_{uuid4().hex[:16]}"


# --- label logic shared by every store -------------------------------------------------------------

def apply_untrusted(label: SessionLabel, source: LabelSource) -> None:
    label.untrusted_sources.append(source)
    if len(label.untrusted_sources) > MAX_SOURCES_PER_LABEL:
        # One untrusted source is enough to mark the label; the rest are kept for display only.
        del label.untrusted_sources[1:-MAX_SOURCES_PER_LABEL // 2]


def apply_private(label: SessionLabel, source: LabelSource) -> None:
    if len(label.private_sources) >= MAX_SOURCES_PER_LABEL:
        # Fold the history into one entry carrying its meet, so the readers never widen.
        label.private_sources = [LabelSource("compacted", "*", "earlier-reads", label.readers or frozenset())]
    label.private_sources.append(source)


def apply_widen(label: SessionLabel, event_id: str, extra: frozenset[str]) -> frozenset[str] | None:
    """Adds readers named by the tool output itself (e.g. the customer a CRM row belongs to)."""
    for index, source in enumerate(label.private_sources):
        if source.event_id == event_id:
            widened = source.readers | extra
            label.private_sources[index] = LabelSource(source.event_id, source.tool, source.action, widened)
            return widened
    return None


class MemorySessionStore:
    """Labels in this process's memory: fine for one worker; lost on restart (see RedisSessionStore)."""

    def __init__(self) -> None:
        self._items: dict[str, SessionLabel] = {}
        self._lock = Lock()

    def create(self, agent_id: str, purpose: str = "") -> SessionLabel:
        label = SessionLabel(session_id=new_session_id(), agent_id=agent_id, purpose=purpose)
        with self._lock:
            self._items[label.session_id] = label
        return label

    def get(self, session_id: str) -> SessionLabel | None:
        return self._items.get(session_id)

    def resolve(self, agent_id: str, session_id: str | None) -> SessionLabel | None:
        """The label for this request, or None if the session does not exist, is closed or is not this agent's."""
        if session_id is None or session_id == default_session_id(agent_id):
            with self._lock:
                key = default_session_id(agent_id)
                if key not in self._items:
                    self._items[key] = SessionLabel(session_id=key, agent_id=agent_id, purpose="default")
                return self._items[key]
        label = self._items.get(session_id)
        if label is None or label.closed or label.agent_id != agent_id:
            return None
        return label

    def close(self, session_id: str) -> SessionLabel | None:
        label = self._items.get(session_id)
        if label is not None and not session_id.startswith("default:"):
            label.closed = True
        return label

    def add_untrusted(self, label: SessionLabel, source: LabelSource) -> None:
        with self._lock:
            apply_untrusted(label, source)

    def add_private(self, label: SessionLabel, source: LabelSource) -> None:
        with self._lock:
            apply_private(label, source)

    def widen_private_readers(self, label: SessionLabel, event_id: str, extra: frozenset[str]) -> frozenset[str] | None:
        with self._lock:
            return apply_widen(label, event_id, extra)

    def list(self) -> list[SessionLabel]:
        return list(self._items.values())


SessionStore = MemorySessionStore  # the name used before there were two stores
