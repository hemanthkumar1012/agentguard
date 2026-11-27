"""Document fingerprints with winnowing, plus bounded decoding of encoded text.

Winnowing is the algorithm behind Stanford's MOSS plagiarism detector (Schleimer, Wilkerson and
Aiken, "Winnowing: Local Algorithms for Document Fingerprinting", SIGMOD 2003):

1. normalise the text (lower case, drop everything that is not a letter or digit);
2. hash every k-character substring (k-gram) with a rolling hash;
3. slide a window of w hashes and keep the smallest hash in each window.

Guarantee: if two texts share a run of at least w + k - 1 normalised characters, they share at
least one fingerprint. With K=10 and W=6 that is 15 characters, so an API key, an address line
or a row of a table is caught, while matches shorter than K characters are ignored as noise.
Because the choice is local, the same substring gives the same fingerprints wherever it appears,
which is what lets AgentGuard find a tool's private output inside a later email body.
"""
from __future__ import annotations

import base64
import binascii
from collections import deque
from functools import lru_cache
import re
from urllib.parse import unquote

import numpy as np
from numpy.lib.stride_tricks import sliding_window_view

K = 10
W = 6
GUARANTEED_MATCH_LENGTH = W + K - 1

# Hashes are polynomials modulo 2**64, so numpy's wrapping uint64 arithmetic computes exactly the
# same values as the pure-Python reference below. (A power-of-two modulus makes deliberate
# collisions easy to construct, but a collision can only create a false match, never hide a leak.)
_MASK = (1 << 64) - 1
_BASE = 1_000_003
_HIGH = pow(_BASE, K - 1, 1 << 64)
_POWERS = np.array([pow(_BASE, K - 1 - j, 1 << 64) for j in range(K)], dtype=np.uint64)
_NOT_ALNUM = re.compile(r"[\W_]+")

# Decoding is attacker-controlled work, so it is bounded: at most this many tokens per text,
# this many decoded characters in total, and two layers (e.g. URL-encoded base64).
MAX_DECODE_TOKENS = 64
MAX_DECODED_CHARS = 200_000
MAX_DECODE_DEPTH = 2
MIN_PRINTABLE_RATIO = 0.85

_BASE64_TOKEN = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
_HEX_TOKEN = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){8,}(?![0-9a-fA-F])")
_URL_ESCAPE = re.compile(r"%[0-9a-fA-F]{2}")


def normalise(text: str) -> str:
    return _NOT_ALNUM.sub("", text.lower())


def kgram_hashes(normalised: str, k: int = K) -> list[int]:
    """Reference implementation: Rabin-Karp rolling hash of every k-gram, O(n). Readable, slow."""
    if len(normalised) < k:
        return []
    high = _HIGH if k == K else pow(_BASE, k - 1, 1 << 64)
    value = 0
    for ch in normalised[:k]:
        value = (value * _BASE + ord(ch)) & _MASK
    hashes = [value]
    for i in range(k, len(normalised)):
        value = ((value - ord(normalised[i - k]) * high) * _BASE + ord(normalised[i])) & _MASK
        hashes.append(value)
    return hashes


def winnow(hashes: list[int], w: int = W) -> set[int]:
    """Reference implementation: smallest hash of every window of w hashes, monotonic deque, O(n)."""
    if not hashes:
        return set()
    if len(hashes) <= w:
        return {min(hashes)}
    selected: set[int] = set()
    window: deque[int] = deque()  # indices whose hashes increase from left to right
    for i, value in enumerate(hashes):
        while window and hashes[window[-1]] >= value:
            window.pop()
        window.append(i)
        if window[0] <= i - w:
            window.popleft()
        if i >= w - 1:
            selected.add(hashes[window[0]])
    return selected


def fingerprints(text: str) -> set[int]:
    """Same result as winnow(kgram_hashes(normalise(text))), vectorised with numpy.

    The Python loops above cost about 7 ms for a 10 KB email body, which was 90% of the decision
    time (profiled 2026-11-27). Here each k-gram hash is a dot product of a sliding window of code
    points with the powers of the base, and each window minimum is a vectorised min.
    tests/test_winnow.py checks that both implementations give identical fingerprints.
    """
    normalised = normalise(text)
    if len(normalised) < K:
        return set()
    codes = np.frombuffer(normalised.encode("utf-32-le"), dtype=np.uint32).astype(np.uint64)
    with np.errstate(over="ignore"):
        hashes = sliding_window_view(codes, K) @ _POWERS
    if len(hashes) <= W:
        return {int(hashes.min())}
    return set(np.unique(sliding_window_view(hashes, W).min(axis=1)).tolist())


def _printable(text: str) -> bool:
    if not text:
        return False
    good = sum(1 for ch in text if ch.isprintable() or ch in "\n\r\t")
    return good / len(text) >= MIN_PRINTABLE_RATIO


def _try_base64(token: str) -> str | None:
    stripped = token.rstrip("=")
    if len(stripped) < 16:
        return None
    padded = stripped + "=" * (-len(stripped) % 4)
    for altchars in (b"+/", b"-_"):
        try:
            raw = base64.b64decode(padded, altchars=altchars, validate=True)
            decoded = raw.decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if _printable(decoded):
            return decoded
    return None


def _try_hex(token: str) -> str | None:
    try:
        decoded = bytes.fromhex(token).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    return decoded if _printable(decoded) else None


def decoded_variants(text: str, depth: int = MAX_DECODE_DEPTH) -> list[tuple[str, str]]:
    """See _decoded_variants. Cached: the inspector, the fingerprint index and the piece tracker all decode
    the same outbound text, which tripled the decoding cost per request (profiled 2026-11-27)."""
    return list(_decoded_variants(text, depth))


@lru_cache(maxsize=16)
def _decoded_variants(text: str, depth: int = MAX_DECODE_DEPTH) -> tuple[tuple[str, str], ...]:
    """Readable texts hidden in `text` as base64, hex or URL encoding, as (encoding, decoded) pairs.

    Random bytes (git SHAs, UUIDs, image data) do not decode to printable UTF-8 and are dropped,
    which keeps hashes and IDs from turning into findings.
    """
    results: list[tuple[str, str]] = []
    budget = [MAX_DECODED_CHARS]

    def visit(current: str, chain: str, level: int) -> None:
        if level >= depth:
            return
        candidates: list[tuple[str, str]] = []
        if _URL_ESCAPE.search(current):
            unquoted = unquote(current)
            if unquoted != current:
                candidates.append(("url", unquoted))
        tokens = 0
        for match in _HEX_TOKEN.finditer(current):
            if tokens >= MAX_DECODE_TOKENS:
                break
            tokens += 1
            decoded = _try_hex(match.group())
            if decoded:
                candidates.append(("hex", decoded))
        for match in _BASE64_TOKEN.finditer(current):
            if tokens >= MAX_DECODE_TOKENS:
                break
            token = match.group()
            if _HEX_TOKEN.fullmatch(token):
                continue  # already tried as hex
            tokens += 1
            decoded = _try_base64(token)
            if decoded:
                candidates.append(("base64", decoded))
        for encoding, decoded in candidates:
            if budget[0] <= 0:
                return
            decoded = decoded[: budget[0]]
            budget[0] -= len(decoded)
            name = f"{chain}+{encoding}" if chain else encoding
            results.append((name, decoded))
            visit(decoded, name, level + 1)

    visit(text, "", 0)
    return tuple(results)
