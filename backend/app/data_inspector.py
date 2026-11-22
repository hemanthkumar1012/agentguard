import re


PATTERNS = {
    "email": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
    "api_key": re.compile(r"\b(?:sk|pk|api)[-_][A-Za-z0-9_-]{16,}\b", re.I),
    "card_number": re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
    "secret_marker": re.compile(r"\b(?:password|secret|private[_ -]?key|access[_ -]?token)\s*[:=]", re.I),
}

# Deeper nesting than this is not scanned, so it is reported as a finding instead of being skipped silently.
MAX_PAYLOAD_DEPTH = 8


def inspect(text: str) -> dict:
    findings = [name for name, pattern in PATTERNS.items() if pattern.search(text)]
    return {"contains_sensitive_data": bool(findings), "findings": findings}


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
        result["findings"].append("payload_too_deep")
        result["contains_sensitive_data"] = True
    return result
