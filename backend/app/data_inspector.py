"""Finds secrets and personal data in text that is about to leave through a tool.

Each detector has a severity:

- HIGH findings (keys, tokens, passwords, card numbers, Aadhaar/PAN numbers) force a human
  approval before the data can leave.
- LOW findings (email addresses, phone numbers) are recorded for the audit trail but do not by
  themselves stop a request. Before 2026-11-27 an email address forced approval, so every
  send_email needed a human because the recipient's own address counted as a finding. Approvals
  that fire on everything get approved without being read, which is worse than no approval.

Validators remove look-alikes: card numbers must pass the Luhn check AND start with a real card
network prefix, Aadhaar numbers must pass the Verhoeff checksum, and the entropy detector skips
hex strings (git SHAs, UUIDs, hashes) and base64 that decodes to ordinary text.
Encoded text (base64, hex, URL encoding) is decoded, within bounds, and scanned again.

Detection quality is measured on a labelled corpus: see bench/ and docs/benchmarks.md.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import math
import re
from typing import Callable

from app.flow.winnow import _try_base64, decoded_variants

HIGH = "high"
LOW = "low"

# Deeper nesting than this is not scanned, so it is reported as a finding instead of being skipped silently.
MAX_PAYLOAD_DEPTH = 8
ENTROPY_THRESHOLD = 3.5      # bits per character
WORD_LIKENESS_LIMIT = 0.6   # above this the token reads like an identifier made of words
ENTROPY_MIN_LENGTH = 24
ENTROPY_MAX_LENGTH = 200     # longer tokens are blobs (images, archives), not credentials


def luhn_valid(digits: str) -> bool:
    total = 0
    for index, ch in enumerate(reversed(digits)):
        value = int(ch)
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def card_network(digits: str) -> str | None:
    n = len(digits)
    two, three, four = int(digits[:2]), int(digits[:3]), int(digits[:4])
    if digits[0] == "4" and n in (13, 16, 19):
        return "visa"
    if (51 <= two <= 55 or 2221 <= four <= 2720) and n == 16:
        return "mastercard"
    if two in (34, 37) and n == 15:
        return "amex"
    if (two in (60, 65, 81, 82) or three == 508) and n == 16:
        return "rupay"
    if (four == 6011 or 644 <= three <= 649 or two == 65) and 16 <= n <= 19:
        return "discover"
    if 3528 <= four <= 3589 and 16 <= n <= 19:
        return "jcb"
    if (300 <= three <= 305 or two in (36, 38, 39)) and 14 <= n <= 19:
        return "diners"
    return None


def _card_valid(match: re.Match) -> bool:
    digits = re.sub(r"\D", "", match.group())
    return 13 <= len(digits) <= 19 and len(set(digits)) > 1 and card_network(digits) is not None and luhn_valid(digits)


# Verhoeff checksum, used by UIDAI for the last digit of an Aadhaar number.
_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7], [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]
_VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def verhoeff_valid(digits: str) -> bool:
    check = 0
    for index, ch in enumerate(reversed(digits)):
        check = _VERHOEFF_D[check][_VERHOEFF_P[index % 8][int(ch)]]
    return check == 0


def verhoeff_check_digit(digits: str) -> str:
    check = 0
    for index, ch in enumerate(reversed(digits)):
        check = _VERHOEFF_D[check][_VERHOEFF_P[(index + 1) % 8][int(ch)]]
    return str(_VERHOEFF_INV[check])


_AADHAAR_CONTEXT = re.compile(r"aadh?aar|\buid\b|uidai|आधार", re.I)


def _aadhaar_valid(match: re.Match) -> bool:
    digits = re.sub(r"\D", "", match.group())
    if len(digits) != 12 or len(set(digits)) <= 2 or not verhoeff_valid(digits):
        return False
    # The checksum alone passes 1 in 10 random 12-digit numbers (UPI references, account numbers),
    # so also require the usual 4-4-4 grouping or the word Aadhaar/UID shortly before the number.
    grouped = re.fullmatch(r"\d{4}[ -]\d{4}[ -]\d{4}", match.group()) is not None
    before = match.string[max(0, match.start() - 40):match.start()]
    return grouped or _AADHAAR_CONTEXT.search(before) is not None


def shannon_entropy(token: str) -> float:
    counts = Counter(token)
    length = len(token)
    return -sum(c / length * math.log2(c / length) for c in counts.values())


_HEX_ONLY = re.compile(r"^[0-9a-fA-F-]+$")


_LOWER_RUN = re.compile(r"[a-z]{3,}")


def word_likeness(token: str) -> float:
    """Share of the token made of runs of 3+ lower-case letters.

    Identifiers are built from words (fetchOrderTimelineV2Handler: 0.81) while random tokens are
    not (99% of random 24-character base62 tokens score 0.50 or less). Entropy alone cannot tell
    them apart: both score about 3.8-4.3 bits per character at this length.
    """
    return sum(len(run) for run in _LOWER_RUN.findall(token)) / len(token)


def _high_entropy(match: re.Match) -> bool:
    token = match.group()
    if _HEX_ONLY.match(token):
        return False  # git SHAs, UUIDs and digests are hex; hex secrets are left to the other detectors
    if not (re.search(r"[a-z]", token) and re.search(r"[A-Z]", token) and re.search(r"\d", token)):
        return False
    if _try_base64(token) is not None:
        return False  # encoded readable text, scanned after decoding instead
    return shannon_entropy(token) >= ENTROPY_THRESHOLD and word_likeness(token) < WORD_LIKENESS_LIMIT


_MASKED = re.compile(r"^[*•x#.]{3,}$|^<[^>]*>$|^\[?redacted\]?$|^(?:your|example|my)[_-]?\w*$|^changeme$|^\$\{", re.I)


def _real_secret_value(match: re.Match) -> bool:
    """`password: ********`, `api_key=YOUR_API_KEY` and `${DB_PASSWORD}` are not secrets."""
    value = re.split(r"[:=]", match.group(), maxsplit=1)[1].strip().strip("\"'`,;")
    return bool(value) and _MASKED.match(value) is None


@dataclass(frozen=True)
class Detector:
    name: str
    pattern: re.Pattern
    severity: str
    validate: Callable[[re.Match], bool] | None = None


def _d(name, regex, severity=HIGH, validate=None, flags=0):
    return Detector(name, re.compile(regex, flags), severity, validate)


DETECTORS: list[Detector] = [
    _d("private_key", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY"),
    _d("aws_access_key", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    _d("github_token", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b"),
    _d("google_api_key", r"\bAIza[0-9A-Za-z_-]{35}\b"),
    _d("slack_token", r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    _d("stripe_key", r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b"),
    _d("jwt", r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    _d("api_key", r"\b(?:sk|pk|api)[-_][A-Za-z0-9_-]{16,}\b", flags=re.I),
    _d("bearer_token", r"\bbearer\s+[A-Za-z0-9._~+/-]{16,}=*", flags=re.I),
    # (?<![A-Za-z]) instead of \b so DB_PASSWORD=... and AWS_SECRET_ACCESS_KEY=... are caught too
    _d("secret_marker",
       r"(?<![A-Za-z])(?:password|passwd|pwd|secret(?:[_ -]?access[_ -]?key)?|client[_ -]?secret|private[_ -]?key"
       r"|access[_ -]?token|api[_ -]?key)\s*[:=]\s*[^\s,;]+", flags=re.I, validate=_real_secret_value),
    _d("credential_in_url", r"\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]{3,}@[^\s/]+", flags=re.I),
    _d("card_number", r"(?<![\d-])(?:\d[ -]?){12,18}\d(?!\d)", validate=_card_valid),
    _d("aadhaar_number", r"(?<!\d)[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?!\d)", validate=_aadhaar_valid),
    _d("pan_number", r"\b[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z]\b"),
    _d("high_entropy_secret",
       # "=" only as base64 padding at the end, so "d=<token>" in a URL yields the token itself
       rf"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{{{ENTROPY_MIN_LENGTH},{ENTROPY_MAX_LENGTH}}}={{0,2}}(?![A-Za-z0-9+/_=-])",
       validate=_high_entropy),
    _d("email", r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b", severity=LOW),
    _d("phone_number", r"(?<![\d+])(?:\+?91[ -]?)?[6-9]\d{4}[ -]?\d{5}(?!\d)", severity=LOW),
]
SEVERITY = {d.name: d.severity for d in DETECTORS} | {"payload_too_deep": HIGH}


def _scan(text: str) -> list[str]:
    found: list[str] = []
    for detector in DETECTORS:
        for match in detector.pattern.finditer(text):
            if detector.validate is None or detector.validate(match):
                found.append(detector.name)
                break
    return found


def severity_of(finding: str) -> str:
    return SEVERITY.get(finding.split(":", 1)[0], HIGH)


def _result(findings: list[str]) -> dict:
    unique = list(dict.fromkeys(findings))
    blocking = [f for f in unique if severity_of(f) == HIGH]
    return {"contains_sensitive_data": bool(unique), "findings": unique, "blocking": blocking}


def inspect(text: str) -> dict:
    findings = _scan(text)
    for encoding, decoded in decoded_variants(text):
        findings += [f"{name}:{encoding}" for name in _scan(decoded)]
    return _result(findings)


def _payload_strings(value, depth: int, out: list[str]) -> bool:
    """Collects every key and value as text. Returns False if the payload is nested too deeply."""
    if depth > MAX_PAYLOAD_DEPTH:
        return False
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, dict):
        for key, item in value.items():
            out.append(str(key))
            if not _payload_strings(item, depth + 1, out):
                return False
    elif isinstance(value, (list, tuple)):
        for item in value:
            if not _payload_strings(item, depth + 1, out):
                return False
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        out.append(str(value))  # card numbers can arrive as plain numbers
    return True


def inspect_outbound(content: str | None, payload: dict | None) -> dict:
    """Inspects everything that leaves through the tool: the declared content AND the execution payload.

    Inspecting only `content` let an agent put secrets in the payload, which is what the tool actually
    receives, and pass the check (found with the attack simulator, scenario secret-in-tool-payload).
    """
    parts: list[str] = [content] if content else []
    complete = _payload_strings(payload or {}, 0, parts)
    result = inspect("\n".join(parts))
    if not complete:
        result = _result(result["findings"] + ["payload_too_deep"])
    return result
