import re


PATTERNS = {
    "email": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
    "api_key": re.compile(r"\b(?:sk|pk|api)[-_][A-Za-z0-9_-]{16,}\b", re.I),
    "card_number": re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
    "secret_marker": re.compile(r"\b(?:password|secret|private[_ -]?key|access[_ -]?token)\s*[:=]", re.I),
}


def inspect(text: str) -> dict:
    findings = [name for name, pattern in PATTERNS.items() if pattern.search(text)]
    return {"contains_sensitive_data": bool(findings), "findings": findings}
