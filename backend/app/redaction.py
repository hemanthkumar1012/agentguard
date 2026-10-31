"""Deterministic PII / secret redaction used by the ALLOW_WITH_REDACTION decision."""

from __future__ import annotations

import re
from typing import Any

# Order matters: more specific patterns run first so that, for example, an API key
# is not partially consumed by the generic long-digit pattern.
_RULES: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("api_key", re.compile(r"\b(?:sk|pk|api)[-_][A-Za-z0-9_-]{16,}\b", re.I), "[REDACTED_API_KEY]"),
    (
        "secret",
        re.compile(r"(?i)\b(password|secret|private[_ -]?key|access[_ -]?token)(\s*[:=]\s*)\S+"),
        r"\1\2[REDACTED_SECRET]",
    ),
    ("email", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"), "[REDACTED_EMAIL]"),
    ("card_number", re.compile(r"\b(?:\d[ -]?){13,19}\b"), "[REDACTED_CARD]"),
    ("aadhaar", re.compile(r"\b\d{4}\s\d{4}\s\d{4}\b"), "[REDACTED_ID]"),
    ("pan", re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"), "[REDACTED_ID]"),
    ("phone", re.compile(r"(?<!\d)(?:\+?91[- ]?)?[6-9]\d{9}(?!\d)"), "[REDACTED_PHONE]"),
)


def redact_text(text: str) -> tuple[str, list[str]]:
    """Return redacted text and the sorted list of categories that were replaced."""
    categories: set[str] = set()
    result = text
    for name, pattern, replacement in _RULES:
        result, count = pattern.subn(replacement, result)
        if count:
            categories.add(name)
    return result, sorted(categories)


def redact_value(value: Any) -> tuple[Any, list[str]]:
    """Recursively redact every string inside dicts, lists and tuples."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        found: set[str] = set()
        out: dict = {}
        for key, item in value.items():
            new_item, cats = redact_value(item)
            out[key] = new_item
            found.update(cats)
        return out, sorted(found)
    if isinstance(value, (list, tuple)):
        found = set()
        items = []
        for item in value:
            new_item, cats = redact_value(item)
            items.append(new_item)
            found.update(cats)
        return (items if isinstance(value, list) else tuple(items)), sorted(found)
    return value, []
