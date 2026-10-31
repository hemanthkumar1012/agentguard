"""Heuristic prompt-injection detection for untrusted text.

This is a *signal*, not the security boundary. The boundary is the policy gateway:
even when an agent is fully compromised, the gateway decides on actions, identity,
ownership and risk. The detector raises risk and gives policies something to match.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

# (category, weight, pattern). Weights are summed and capped at 100.
_PATTERNS: tuple[tuple[str, int, re.Pattern[str]], ...] = (
    ("instruction-override", 45, re.compile(r"\b(ignore|disregard|forget|override)\b.{0,40}\b(previous|prior|above|earlier|system|all)\b.{0,30}\b(instruction|prompt|rule|polic|guideline)", re.I | re.S)),
    ("instruction-override", 35, re.compile(r"\bnew (instructions?|rules?|orders?)\b\s*[:\-]", re.I)),
    ("prompt-extraction", 45, re.compile(r"\b(reveal|show|print|repeat|output|leak|display)\b.{0,40}\b(system prompt|hidden instruction|initial instruction|your instructions|developer message)", re.I | re.S)),
    ("role-hijack", 30, re.compile(r"\byou are (now|no longer)\b|\bact as (an? )?(admin|administrator|root|developer|system)\b|\bpretend (to be|you are)\b", re.I)),
    ("authority-claim", 25, re.compile(r"\b(i am|this is|message from) (the )?(admin|administrator|system|developer|security team|ceo|your (owner|creator))\b", re.I)),
    ("authority-claim", 20, re.compile(r"\b(maintenance|debug|developer|god|sudo|admin) mode\b|\bsudo\b|\bpolicy (is )?(disabled|suspended|waived)\b", re.I)),
    ("bulk-data-access", 40, re.compile(r"\b(all|every|entire|full)\b.{0,25}\b(customer|user|account|client)s?\b.{0,25}\b(record|data|detail|list|database|information|email)s?\b", re.I | re.S)),
    ("bulk-data-access", 35, re.compile(r"\b(dump|export|exfiltrat\w*|download)\b.{0,30}\b(database|customers?|records?|users?|table)\b", re.I | re.S)),
    ("external-exfiltration", 45, re.compile(r"\b(send|forward|email|post|upload|transmit)\b.{0,60}\b(to|at)\b.{0,20}([\w.+-]+@[\w-]+\.[\w.-]+|https?://\S+)", re.I | re.S)),
    ("privileged-tool-call", 40, re.compile(r"\b(call|invoke|run|execute|use)\b.{0,30}\b(refund|transfer|delete|export|admin|payout|cancel)\w*\b.{0,40}\b(api|tool|function|endpoint|account|admin)", re.I | re.S)),
    ("privileged-tool-call", 30, re.compile(r"\b(refund|transfer|send|pay)\b.{0,30}(₹|rs\.?|inr|usd|\$)\s?\d", re.I | re.S)),
    ("delimiter-spoof", 25, re.compile(r"(<\|?(system|im_start|im_end)\|?>|\[/?(INST|SYSTEM)\]|^#{2,}\s*system\b)", re.I | re.M)),
    ("obfuscation", 25, re.compile(r"\b(base64|rot13|hex[- ]?encoded|decode (this|the following))\b", re.I)),
    ("secrecy", 20, re.compile(r"\b(do not|don't|never) (tell|inform|notify|mention|alert) (the )?(user|customer|human|operator|anyone)\b", re.I)),
)

_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
_ZERO_WIDTH = re.compile("[​‌‍⁠﻿]")


@dataclass(frozen=True)
class InjectionReport:
    score: int
    categories: tuple[str, ...]
    source: str

    @property
    def detected(self) -> bool:
        return self.score >= INJECTION_THRESHOLD


INJECTION_THRESHOLD = 40


def normalize(text: str) -> str:
    """Fold unicode tricks (zero-width characters, homoglyph-ish forms, spacing)."""
    folded = unicodedata.normalize("NFKC", text)
    folded = _ZERO_WIDTH.sub("", folded)
    return re.sub(r"[ \t]+", " ", folded)


def scan(text: str | None, source: str = "user") -> InjectionReport:
    """Score `text` for injected-instruction patterns.

    The user's own message is trusted to *ask* for things, so it is only scored at
    half weight; the policy layer, not this detector, decides whether the ask is allowed.
    Untrusted sources (documents, tool output, email, ...) are scored at full weight.
    """
    if not text:
        return InjectionReport(0, (), source)
    variants = {normalize(text)}
    # Catch leetspeak evasions ("1gn0re pr3vious") without mangling the original text.
    variants.add(normalize(text).translate(_LEET))
    best: dict[str, int] = {}
    for variant in variants:
        for category, weight, pattern in _PATTERNS:
            if pattern.search(variant):
                best[category] = max(best.get(category, 0), weight)
    raw = min(100, sum(best.values()))
    if len(best) >= 2:
        raw = min(100, raw + 10)  # multiple independent signals are more suspicious
    score = raw if source != "user" else raw // 2
    return InjectionReport(score, tuple(sorted(best)), source)
