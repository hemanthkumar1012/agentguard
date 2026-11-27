"""Catches a secret that leaves in pieces, one request at a time.

Winnowing only sees runs of 15+ characters, so a token sent as "part 1: rzp_live", "part 2: _Q8wT2kL", ...
passed every other layer. This tracker keeps, for each short *secret-like* value a private tool returned
(something the inspector rates high severity: keys, tokens, card numbers), the set of its 4-character
pieces (q-grams). For every outbound request it records which pieces went to which destination domain,
and adds them up across requests. Once more than half of a secret's pieces have reached one domain that
may not read it, rule F5 fires.

Choices:
- q = 4: with q = 6, pieces cut at 8 characters lost the q-grams that span the cuts and only 39% of a
  23-character token was visible; with q = 4 it is 65%. Pieces of 3 characters or fewer still pass
  (known gap, shown in the benchmark).
- only secret-like values, at most 256 characters: q-grams of names and addresses ("tiru", "nagar")
  appear in ordinary text and would add up to false matches; q-grams of random tokens do not.
- keyed by destination *domain*, so rotating addresses at the attacker's domain does not reset the count.
- a 24-hour window and size caps bound the memory.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import os
from threading import Lock
from urllib.parse import urlparse

import numpy as np
from numpy.lib.stride_tricks import sliding_window_view

from app.flow.winnow import decoded_variants, normalise

Q = 4
MIN_SECRET_LENGTH = 8       # normalised characters
MAX_SECRET_LENGTH = 256
COVERAGE_THRESHOLD = 0.5
WINDOW = timedelta(hours=24)
MAX_SECRETS_PER_AGENT = 512
MAX_TRACKED_PAIRS_PER_AGENT = 4096


# Overlapping 4-character pieces of a token spell the token out, so they are not stored as text: each
# piece becomes a polynomial hash of its code points, mixed with a random per-process key. That keeps
# secrets out of logs and dumps of the structure; it is not protection against someone who can read
# this process's memory (the key is there too, and the plaintext secret passed through anyway).
# Vectorised with numpy: hashing each piece with blake2b cost about 7 ms per 10 KB request.
_KEY = np.uint64(int.from_bytes(os.urandom(8), "little"))
_MIX = np.uint64(0x9E3779B97F4A7C15)
_POWERS = np.array([1_000_003 ** (Q - 1 - j) % (1 << 64) for j in range(Q)], dtype=np.uint64)


def qgrams(text: str) -> set[int]:
    normalised = normalise(text)
    if len(normalised) < Q:
        return set()
    codes = np.frombuffer(normalised.encode("utf-32-le"), dtype=np.uint32).astype(np.uint64)
    with np.errstate(over="ignore"):
        hashed = ((sliding_window_view(codes, Q) @ _POWERS) ^ _KEY) * _MIX
    return set(np.unique(hashed).tolist())


def destination_key(destination: str) -> str:
    """The thing an attacker controls: the email domain, the URL host, or the destination itself."""
    value = destination.strip().lower()
    if "://" in value:
        return urlparse(value).hostname or value
    if "@" in value and " " not in value:
        return value.rsplit("@", 1)[1]
    return value


@dataclass(frozen=True)
class Secret:
    secret_id: str
    source_id: str
    tool: str
    action: str
    readers: frozenset[str]
    grams: frozenset[int]


@dataclass
class Exposure:
    covered: set[int] = field(default_factory=set)
    requests: int = 0
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(frozen=True)
class PieceMatch:
    secret: Secret
    destination: str
    coverage: float
    requests: int

    def as_dict(self) -> dict:
        return {"source_event_id": self.secret.source_id, "tool": self.secret.tool, "action": self.secret.action,
                "readers": sorted(self.secret.readers), "destination": self.destination,
                "coverage": round(self.coverage, 3), "requests": self.requests, "kind": "pieces"}


class SecretPieceTracker:
    def __init__(self) -> None:
        self._secrets: dict[str, dict[str, Secret]] = {}
        self._by_gram: dict[str, dict[int, set[str]]] = {}
        self._exposure: dict[str, dict[tuple[str, str], Exposure]] = {}
        self._lock = Lock()

    def add(self, *, agent_id: str, source_id: str, tool: str, action: str, readers: frozenset[str], value: str) -> bool:
        length = len(normalise(value))
        if not MIN_SECRET_LENGTH <= length <= MAX_SECRET_LENGTH:
            return False
        grams = frozenset(qgrams(value))
        with self._lock:
            secrets = self._secrets.setdefault(agent_id, {})
            by_gram = self._by_gram.setdefault(agent_id, {})
            secret_id = f"{source_id}:{len(secrets)}"
            if len(secrets) >= MAX_SECRETS_PER_AGENT:
                oldest = next(iter(secrets))
                for gram in secrets.pop(oldest).grams:
                    by_gram.get(gram, set()).discard(oldest)
            secrets[secret_id] = Secret(secret_id, source_id, tool, action, readers, grams)
            for gram in grams:
                by_gram.setdefault(gram, set()).add(secret_id)
        return True

    def has_secrets(self, agent_id: str) -> bool:
        return bool(self._secrets.get(agent_id))

    def observe(self, agent_id: str, destination: str, text: str) -> list[PieceMatch]:
        return self.observe_all(agent_id, [destination], text)

    def observe_all(self, agent_id: str, destinations: list[str], text: str) -> list[PieceMatch]:
        """Records the pieces in `text` as sent to each destination; returns secrets now mostly exposed there."""
        if not self.has_secrets(agent_id):
            return []     # nothing tracked for this agent: skip hashing the request entirely
        sent: set[int] = set(qgrams(text))
        for _, decoded in decoded_variants(text):
            sent |= qgrams(decoded)
        matches: list[PieceMatch] = []
        for destination in destinations:
            matches += self._record(agent_id, destination_key(destination), sent)
        return sorted(matches, key=lambda m: m.coverage, reverse=True)

    def _record(self, agent_id: str, key: str, sent: set[int]) -> list[PieceMatch]:
        now = datetime.now(timezone.utc)
        matches: list[PieceMatch] = []
        with self._lock:
            secrets = self._secrets.get(agent_id, {})
            by_gram = self._by_gram.get(agent_id, {})
            exposure = self._exposure.setdefault(agent_id, {})
            touched: dict[str, set[int]] = {}
            for gram in sent:
                for secret_id in by_gram.get(gram, ()):
                    touched.setdefault(secret_id, set()).add(gram)
            for secret_id, grams in touched.items():
                secret = secrets.get(secret_id)
                if secret is None:
                    continue
                pair = (key, secret_id)
                record = exposure.get(pair)
                if record is None or now - record.first_seen > WINDOW:
                    if len(exposure) >= MAX_TRACKED_PAIRS_PER_AGENT:
                        exposure.pop(next(iter(exposure)))
                    record = exposure[pair] = Exposure(first_seen=now)
                record.covered |= grams
                record.requests += 1
                coverage = len(record.covered) / len(secret.grams)
                if coverage > COVERAGE_THRESHOLD:
                    matches.append(PieceMatch(secret, key, coverage, record.requests))
        return matches
