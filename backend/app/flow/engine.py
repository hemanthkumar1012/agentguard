"""Glue between the gateway and the flow rules.

    check(request)                      before the decision: may tighten it (never loosen it)
    on_allowed(request, event_id)       after an allowed decision: grows the session label
    record_output(request, event_id, o) after AgentGuard ran the tool: fingerprints private output

Modes (AGENTGUARD_FLOW_MODE):
    enforce  the verdict can raise the decision to approval or block (default)
    monitor  the verdict is recorded as risk factors only, so a new rule can be watched on real
             traffic before it is switched on
    off      flow tracking is disabled
"""
from __future__ import annotations

from dataclasses import dataclass

from app.domain import ActionRequest, Decision
from app.flow.fingerprints import FingerprintIndex, flatten_strings
from app.flow.labels import (
    INTERNAL,
    Capability,
    DestinationRegistry,
    ManifestRegistry,
    ToolManifest,
)
from app.flow.policy import FlowVerdict, evaluate_flow
from app.flow.session import LabelSource, MemorySessionStore, SessionLabel

MODES = {"enforce", "monitor", "off"}


def default_manifests() -> list[ToolManifest]:
    """Descriptions for the demo tool and for common actions when no tool-specific manifest exists."""
    cap = Capability
    return [
        ToolManifest("demo", "echo", frozenset()),
        ToolManifest("*", "send_email", frozenset({cap.EGRESS}), destination_field="to"),
        ToolManifest("*", "export_data", frozenset({cap.EGRESS, cap.MUTATES})),
        ToolManifest("*", "http_request", frozenset({cap.EGRESS}), destination_field="url"),
        # A GET request is also an outbound message: the query string can carry data (EchoLeak).
        ToolManifest("*", "fetch_url", frozenset({cap.INGESTS_UNTRUSTED, cap.EGRESS}), destination_field="url"),
        ToolManifest("*", "read_record", frozenset({cap.READS_PRIVATE}), readers=frozenset({INTERNAL})),
        ToolManifest("*", "read_inbox", frozenset({cap.INGESTS_UNTRUSTED})),
        ToolManifest("*", "web_search", frozenset({cap.INGESTS_UNTRUSTED})),
        ToolManifest("*", "delete", frozenset({cap.MUTATES})),
        ToolManifest("*", "transfer_funds", frozenset({cap.MUTATES})),
    ]


@dataclass(frozen=True)
class FlowContext:
    label: SessionLabel
    manifest: ToolManifest
    destination: str
    audience: frozenset[str]


class FlowEngine:
    def __init__(self, manifests: ManifestRegistry | None = None, destinations: DestinationRegistry | None = None,
                 sessions: SessionStore | None = None, index: FingerprintIndex | None = None,
                 mode: str = "enforce") -> None:
        if mode not in MODES:
            raise ValueError(f"flow mode must be one of {sorted(MODES)}")
        self.manifests = manifests or ManifestRegistry(default_manifests())
        self.destinations = destinations or DestinationRegistry()
        self.sessions = sessions or MemorySessionStore()
        self.index = index or FingerprintIndex()
        self.mode = mode

    @property
    def enabled(self) -> bool:
        return self.mode != "off"

    def session_valid(self, request: ActionRequest) -> bool:
        # In monitor mode an unknown session is reported by check() instead of blocked here.
        if self.mode != "enforce":
            return True
        return self.sessions.resolve(request.agent_id, request.session_id) is not None

    def _destinations_of(self, request: ActionRequest, manifest: ToolManifest) -> list[str]:
        value = request.execution_payload.get(manifest.destination_field) if manifest.destination_field else None
        if isinstance(value, str) and value.strip():
            return [part.strip() for part in value.split(",") if part.strip()]
        if isinstance(value, (list, tuple)) and value:
            return [str(part).strip() for part in value if str(part).strip()]
        return [request.target]

    def context(self, request: ActionRequest) -> FlowContext | None:
        label = self.sessions.resolve(request.agent_id, request.session_id)
        if label is None:
            return None
        manifest = self.manifests.resolve(request.tool, request.action)
        destinations = self._destinations_of(request, manifest)
        audience: frozenset[str] = frozenset()
        for destination in destinations:
            audience |= self.destinations.audience(destination)
        return FlowContext(label=label, manifest=manifest, destination=", ".join(destinations), audience=audience)

    def check(self, request: ActionRequest) -> FlowVerdict:
        if not self.enabled:
            return FlowVerdict()
        ctx = self.context(request)
        if ctx is None:
            verdict = FlowVerdict(decision=Decision.BLOCK, rule="F0", factors=["unknown-session"],
                                  reason="Session does not exist, is closed, or belongs to another agent.")
            return self._monitored(verdict)
        matches = []
        if ctx.manifest.has(Capability.EGRESS):
            outbound = "\n".join(
                ([request.content] if request.content else [])
                + flatten_strings(request.execution_payload, include_keys=True)
                + [request.target]
            )
            matches = self.index.match(request.agent_id, outbound)
        verdict = evaluate_flow(action=request.action, manifest=ctx.manifest, label=ctx.label,
                                destination=ctx.destination, audience=ctx.audience, matches=matches)
        if not ctx.manifest.known:
            verdict = FlowVerdict(verdict.decision, verdict.reason, verdict.rule,
                                  ["undescribed-tool-assumed-worst-case", *verdict.factors], verdict.lineage)
        return self._monitored(verdict)

    def _monitored(self, verdict: FlowVerdict) -> FlowVerdict:
        if self.mode == "monitor" and verdict.decision != Decision.ALLOW:
            return FlowVerdict(factors=[*verdict.factors, f"flow-would-{verdict.decision.value}"],
                               lineage=verdict.lineage)
        return verdict

    def on_allowed(self, request: ActionRequest, event_id: str) -> None:
        if not self.enabled:
            return
        ctx = self.context(request)
        if ctx is None:
            return
        name = (request.tool or "*", request.action)
        if ctx.manifest.has(Capability.INGESTS_UNTRUSTED):
            self.sessions.add_untrusted(ctx.label, LabelSource(event_id, *name))
        if ctx.manifest.has(Capability.READS_PRIVATE):
            self.sessions.add_private(ctx.label, LabelSource(event_id, *name, ctx.manifest.readers))

    def record_output(self, request: ActionRequest, event_id: str, output) -> dict:
        """Called with what the tool returned. Returns what was learned, for tests and the audit trail."""
        if not self.enabled:
            return {}
        ctx = self.context(request)
        if ctx is None or not ctx.manifest.has(Capability.READS_PRIVATE):
            return {}
        readers = ctx.manifest.readers
        owners = self._owners(ctx.manifest, output)
        if len(owners) == 1:
            # A single record names the one person it belongs to; that person may read it too.
            readers = self.sessions.widen_private_readers(ctx.label, event_id, frozenset(owners)) or readers
        source = self.index.add(agent_id=request.agent_id, session_id=ctx.label.session_id, source_id=event_id,
                                tool=request.tool or "*", action=request.action, readers=readers, output=output)
        return {
            "readers": sorted(readers),
            "fingerprints": source.fingerprint_count if source else 0,
            # Several owners in one output (a search over many customers) widen nothing: otherwise each
            # customer could be sent every other customer's row.
            "owners_ignored": len(owners) > 1,
        }

    @staticmethod
    def _owners(manifest: ToolManifest, output) -> set[str]:
        owners: set[str] = set()
        if not manifest.readers_from:
            return owners

        def walk(value, depth=0):
            if depth > 8:
                return
            if isinstance(value, dict):
                for key, item in value.items():
                    if key in manifest.readers_from and isinstance(item, str) and "@" in item:
                        owners.add(f"user:{item.strip().lower()}")
                    else:
                        walk(item, depth + 1)
            elif isinstance(value, list):
                for item in value:
                    walk(item, depth + 1)

        walk(output)
        return owners
