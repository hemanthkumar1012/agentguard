"""Remembers fingerprints of private tool output so it can be recognised when it tries to leave.

The session label (app/flow/session.py) answers "could this session leak private data?". This
index answers a different question: "is private data that AgentGuard saw earlier actually inside
this request, and where did it come from?". It is kept per agent, not per session, so data read
in one session and sent in a fresh one (for example through an agent's long-term memory) is
still recognised. It catches verbatim and re-encoded copies; it cannot catch a paraphrase, which
is why the label rule exists as well.
"""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from threading import Lock

from app.flow.winnow import decoded_variants, fingerprints

MAX_SOURCES_PER_AGENT = 256
MAX_FINGERPRINTS_PER_SOURCE = 4096
MIN_SHARED_FINGERPRINTS = 2       # one shared hash can be a coincidence; two in a row rarely is
# A fingerprint held by more sources than this is boilerplate ("your order has been shipped") and
# is ignored when matching, like MOSS's -m option. Identical outputs are stored once, so reading
# the same record many times does not turn it into boilerplate.
MAX_SOURCES_PER_FINGERPRINT = 8
MAX_STRINGS_PER_OUTPUT = 2000
MAX_OUTPUT_DEPTH = 8


@dataclass(frozen=True)
class Source:
    source_id: str            # audit event id of the tool call that returned the data
    agent_id: str
    session_id: str
    tool: str
    action: str
    readers: frozenset[str]
    fingerprint_count: int
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(frozen=True)
class Match:
    source: Source
    shared: int
    coverage: float           # share of the source's fingerprints found in the request
    encoding: str             # "plain", "base64", "url+base64", ...

    def as_dict(self) -> dict:
        return {
            "source_event_id": self.source.source_id,
            "session_id": self.source.session_id,
            "tool": self.source.tool,
            "action": self.source.action,
            "readers": sorted(self.source.readers),
            "shared_fingerprints": self.shared,
            "coverage": round(self.coverage, 3),
            "encoding": self.encoding,
        }


def flatten_strings(value, out: list[str] | None = None, depth: int = 0, include_keys: bool = False) -> list[str]:
    """Every string and number in a JSON-like value, and optionally its keys (bounded in depth and count)."""
    out = [] if out is None else out
    if depth > MAX_OUTPUT_DEPTH or len(out) >= MAX_STRINGS_PER_OUTPUT:
        return out
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, dict):
        for key, item in value.items():
            if include_keys:
                out.append(str(key))
            flatten_strings(item, out, depth + 1, include_keys)
    elif isinstance(value, (list, tuple)):
        for item in value:
            flatten_strings(item, out, depth + 1, include_keys)
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        out.append(str(value))
    return out


class FingerprintIndex:
    def __init__(self, max_sources_per_agent: int = MAX_SOURCES_PER_AGENT,
                 min_shared: int = MIN_SHARED_FINGERPRINTS,
                 max_sources_per_fingerprint: int = MAX_SOURCES_PER_FINGERPRINT) -> None:
        self.max_sources_per_agent = max_sources_per_agent
        self.min_shared = min_shared
        self.max_sources_per_fingerprint = max_sources_per_fingerprint
        self._by_content: dict[str, dict[frozenset[int], str]] = {}
        self._sources: dict[str, OrderedDict[str, tuple[Source, frozenset[int]]]] = {}
        self._inverted: dict[str, dict[int, set[str]]] = {}
        self._lock = Lock()

    def add(self, *, agent_id: str, session_id: str, source_id: str, tool: str, action: str,
            readers: frozenset[str], output) -> Source | None:
        # Each value is fingerprinted on its own, so field names and the joins between fields
        # do not produce fingerprints that would match unrelated text.
        prints: set[int] = set()
        for text in flatten_strings(output):
            prints |= fingerprints(text)
            if len(prints) >= MAX_FINGERPRINTS_PER_SOURCE:
                break
        if not prints:
            return None
        frozen = frozenset(sorted(prints)[:MAX_FINGERPRINTS_PER_SOURCE])
        source = Source(source_id=source_id, agent_id=agent_id, session_id=session_id, tool=tool,
                        action=action, readers=readers, fingerprint_count=len(frozen))
        with self._lock:
            sources = self._sources.setdefault(agent_id, OrderedDict())
            inverted = self._inverted.setdefault(agent_id, {})
            by_content = self._by_content.setdefault(agent_id, {})
            existing = by_content.get(frozen)
            if existing is not None and existing in sources:
                sources.move_to_end(existing)      # same output seen again: keep the first source, refresh it
                return sources[existing][0]
            by_content[frozen] = source_id
            sources[source_id] = (source, frozen)
            for value in frozen:
                inverted.setdefault(value, set()).add(source_id)
            while len(sources) > self.max_sources_per_agent:
                old_id, (_, old_prints) = sources.popitem(last=False)
                by_content.pop(old_prints, None)
                for value in old_prints:
                    holders = inverted.get(value)
                    if holders is not None:
                        holders.discard(old_id)
                        if not holders:
                            del inverted[value]
        return source

    def update_readers(self, agent_id: str, source_id: str, readers: frozenset[str]) -> None:
        with self._lock:
            entry = self._sources.get(agent_id, {}).get(source_id)
            if entry is not None:
                source, prints = entry
                self._sources[agent_id][source_id] = (
                    Source(**{**source.__dict__, "readers": readers}), prints)

    def match(self, agent_id: str, text: str) -> list[Match]:
        """Sources whose fingerprints appear in `text`, in plain form or after decoding."""
        with self._lock:
            sources = dict(self._sources.get(agent_id, {}))
            inverted = self._inverted.get(agent_id, {})
            if not sources:
                return []
            best: dict[str, Match] = {}
            for encoding, variant in [("plain", text), *decoded_variants(text)]:
                counts: dict[str, int] = {}
                for value in fingerprints(variant):
                    holders = inverted.get(value)
                    if not holders or len(holders) > self.max_sources_per_fingerprint:
                        continue
                    for source_id in holders:
                        counts[source_id] = counts.get(source_id, 0) + 1
                for source_id, shared in counts.items():
                    source, prints = sources[source_id]
                    if shared < min(self.min_shared, len(prints)):
                        continue
                    found = Match(source=source, shared=shared, coverage=shared / len(prints), encoding=encoding)
                    if source_id not in best or found.shared > best[source_id].shared:
                        best[source_id] = found
        return sorted(best.values(), key=lambda m: m.shared, reverse=True)

    def count(self, agent_id: str) -> int:
        return len(self._sources.get(agent_id, {}))
