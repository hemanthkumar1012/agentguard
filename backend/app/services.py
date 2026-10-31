import os
from pathlib import Path

from app.agent_auth import AgentAuthorization
from app.audit import AuditLedger
from app.approvals import ApprovalStore
from app.budgets import BudgetManager
from app.credentials import CredentialBroker
from app.gateway import ToolGateway
from app.identity import AgentRegistry
from app.policy_engine import PolicyEngine, default_engine
from app.supabase_store import SupabaseStore


def _load_policy_engine() -> PolicyEngine:
    """Load AGENTGUARD_POLICY_FILE when configured; otherwise use the built-in fintech pack.

    A configured file that fails to load is a startup error: falling back to defaults
    would silently run with a policy the operator did not choose.
    """
    configured = os.getenv("AGENTGUARD_POLICY_FILE")
    if not configured:
        return default_engine()
    path = Path(configured)
    if not path.is_absolute():
        path = Path(__file__).resolve().parents[2] / path
    return PolicyEngine.from_file(path)


# Shared runtime services. Supabase becomes the durable adapter when both
# server-side credentials are configured; local development remains zero-config.
persistence = SupabaseStore.from_env()
agent_registry = AgentRegistry(store=persistence)
audit_ledger = AuditLedger(store=persistence)
credential_broker = CredentialBroker(store=persistence)
approval_store = ApprovalStore(store=persistence)
policy_engine = _load_policy_engine()
tool_gateway = ToolGateway(agent_registry, audit_ledger, credential_broker, approval_store, engine=policy_engine)
delegation_authorizer = AgentAuthorization(agent_registry, store=persistence)
budget_manager = BudgetManager()


def _build_runtime():
    # Imported lazily so the core enforcement modules never depend on the agent runtime.
    from app.agent_runtime import AgentRunner, AgentVersionStore, default_versions
    from app.evaluation import EvaluationEngine
    from app.fintech import FintechStore
    from app.orchestrator import Orchestrator
    from app.tracing import TraceStore

    store = FintechStore()
    traces = TraceStore(store=persistence)
    versions = AgentVersionStore(agent_registry)
    for version in default_versions():
        versions.add(version)
    runner = AgentRunner(agent_registry, tool_gateway, credential_broker, traces, budget_manager, store, versions)
    orchestrator = Orchestrator(agent_registry, delegation_authorizer, runner.tools, traces)
    evaluations = EvaluationEngine(runner, versions)
    return store, traces, versions, runner, orchestrator, evaluations


fintech_store, trace_store, agent_versions, agent_runner, orchestrator, evaluation_engine = _build_runtime()
