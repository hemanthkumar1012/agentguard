"""Who may read a piece of data, and who will read what an agent sends.

AgentGuard uses reader sets, the idea behind the decentralized label model (Myers and Liskov):

- every piece of private data says which principals may read it (its *readers*);
- every destination has an *audience*, the principals who will be able to read what is sent there;
- data may flow to a destination only if every member of the audience is an allowed reader.

Principals are plain strings:

    "*"                    everyone (a public repository, an unknown web endpoint)
    "user:priya@acme.com"  one person
    "domain:acme.com"      anyone with an @acme.com address
    "internal"             systems the operator has registered as internal
    "group:<name>"         any other named group, matched exactly
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from fnmatch import fnmatchcase
import re
from threading import Lock

PUBLIC = "*"
INTERNAL = "internal"
EMAIL = re.compile(r"^[\w.+-]+@([\w-]+(?:\.[\w-]+)+)$")


class Capability(str, Enum):
    READS_PRIVATE = "reads_private"          # output contains private data (CRM row, private repo file)
    INGESTS_UNTRUSTED = "ingests_untrusted"  # output may contain text an attacker wrote (web page, email, ticket)
    EGRESS = "egress"                        # sends data somewhere (email, HTTP call, PR, ticket reply)
    MUTATES = "mutates"                      # changes state (delete, transfer, update)


# A tool nobody described is assumed to be able to send data out, change state and return
# untrusted text. It is NOT assumed to return private data: if every unknown output were private,
# every later request would be blocked and the label would carry no information (label creep).
UNKNOWN_TOOL_CAPABILITIES = frozenset({Capability.EGRESS, Capability.MUTATES, Capability.INGESTS_UNTRUSTED})
DEFAULT_PRIVATE_READERS = frozenset({INTERNAL})


@dataclass(frozen=True)
class ToolManifest:
    tool: str                                   # "*" matches any tool
    action: str                                 # "*" matches any action
    capabilities: frozenset[Capability]
    destination_field: str | None = None        # payload key that names where data goes ("to", "url")
    readers: frozenset[str] = DEFAULT_PRIVATE_READERS   # who may read this tool's private output
    readers_from: tuple[str, ...] = ()          # output fields whose values are extra readers, e.g. "email"
    known: bool = True                          # False for the worst-case manifest of an undescribed tool

    def has(self, capability: Capability) -> bool:
        return capability in self.capabilities


class ManifestRegistry:
    """Describes what each tool action can do. Lookup is exact, then tool-wide, then action-wide."""

    def __init__(self, manifests: list[ToolManifest] | None = None) -> None:
        self._items: dict[tuple[str, str], ToolManifest] = {}
        self._lock = Lock()
        for manifest in manifests or []:
            self.register(manifest)

    def register(self, manifest: ToolManifest) -> ToolManifest:
        with self._lock:
            self._items[(manifest.tool, manifest.action)] = manifest
        return manifest

    def resolve(self, tool: str | None, action: str) -> ToolManifest:
        tool_key = tool or "*"
        for key in ((tool_key, action), (tool_key, "*"), ("*", action)):
            found = self._items.get(key)
            if found is not None:
                return found
        return ToolManifest(tool=tool_key, action=action, capabilities=UNKNOWN_TOOL_CAPABILITIES, known=False)

    def list(self) -> list[ToolManifest]:
        return sorted(self._items.values(), key=lambda m: (m.tool, m.action))


@dataclass(frozen=True)
class DestinationRule:
    pattern: str                 # shell-style pattern, e.g. "slack:#support-*" or "*@acme.com"
    audience: frozenset[str]


@dataclass
class DestinationRegistry:
    """Maps destinations to their audience. Anything not registered is treated as public."""

    rules: list[DestinationRule] = field(default_factory=list)

    def register(self, pattern: str, audience: set[str] | frozenset[str]) -> DestinationRule:
        rule = DestinationRule(pattern=pattern, audience=frozenset(audience))
        self.rules = [r for r in self.rules if r.pattern != pattern] + [rule]
        return rule

    def audience(self, destination: str) -> frozenset[str]:
        value = destination.strip()
        lowered = value.lower()
        for rule in self.rules:
            if fnmatchcase(lowered, rule.pattern.lower()):
                return rule.audience
        if EMAIL.match(lowered):
            # An email is read by its recipient (and, as far as we can tell, nobody else).
            return frozenset({f"user:{lowered}"})
        return frozenset({PUBLIC})


def covers(readers: frozenset[str], principal: str) -> bool:
    """True if `principal` is allowed to read data whose readers are `readers`."""
    if PUBLIC in readers or principal in readers:
        return True
    if principal.startswith("user:"):
        match = EMAIL.match(principal.removeprefix("user:"))
        if match and f"domain:{match.group(1)}" in readers:
            return True
    return False


def flows_to(readers: frozenset[str] | None, audience: frozenset[str]) -> bool:
    """Data readable by `readers` may go to a destination read by `audience`.

    `readers=None` means the session has read no private data, so nothing constrains it.
    """
    if readers is None or PUBLIC in readers:
        return True
    if PUBLIC in audience:
        return False
    return all(covers(readers, principal) for principal in audience)


def meet(a: frozenset[str] | None, b: frozenset[str]) -> frozenset[str]:
    """Readers allowed to see BOTH pieces of data. Reading more private data only shrinks this set."""
    if a is None:
        return b
    if PUBLIC in a:
        return b
    if PUBLIC in b:
        return a
    kept = {p for p in a if covers(b, p)} | {p for p in b if covers(a, p)}
    return frozenset(kept)
