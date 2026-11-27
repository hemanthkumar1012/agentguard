from app.audit import AuditLedger
from app.approvals import ApprovalStore
from app.config import settings
from app.credentials import CredentialBroker
from app.flow.engine import FlowEngine
from app.gateway import ToolGateway
from app.identity import AgentRegistry
from app.supabase_store import SupabaseStore


# Shared runtime services. Supabase becomes the durable adapter when both
# server-side credentials are configured; local development remains zero-config.
persistence = SupabaseStore.from_env()
agent_registry = AgentRegistry(store=persistence)
audit_ledger = AuditLedger(store=persistence)
credential_broker = CredentialBroker(store=persistence)
approval_store = ApprovalStore(store=persistence)
flow_engine = FlowEngine(mode=settings.flow_mode)
tool_gateway = ToolGateway(agent_registry, audit_ledger, credential_broker, approval_store, flow=flow_engine)
