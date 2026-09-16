from dataclasses import dataclass
import hmac


@dataclass(frozen=True)
class Operator:
    role: str


VALID_ROLES = {"admin", "reviewer", "viewer"}


def parse_operator_keys(raw: str | None, legacy_key: str | None) -> tuple[tuple[str, str], ...]:
    entries: list[tuple[str, str]] = []
    if legacy_key:
        entries.append((legacy_key, "admin"))
    for item in (raw or "").split(","):
        item = item.strip()
        if not item:
            continue
        key, separator, role = item.rpartition(":")
        if not separator or not key or role not in VALID_ROLES:
            raise ValueError("AGENTGUARD_OPERATORS entries must use key:admin|reviewer|viewer")
        entries.append((key, role))
    return tuple(entries)


def authenticate(supplied: str | None, configured: tuple[tuple[str, str], ...]) -> Operator | None:
    if not supplied:
        return None
    for expected, role in configured:
        if hmac.compare_digest(supplied, expected):
            return Operator(role)
    return None


def can_access(role: str, method: str, path: str) -> bool:
    if role == "admin":
        return True
    if method in {"GET", "HEAD"}:
        return True
    if role == "reviewer" and method == "POST" and path.startswith("/api/v1/approvals/") and path.endswith("/decision"):
        return True
    return False
