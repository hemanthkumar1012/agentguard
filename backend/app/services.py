from app.audit import AuditLedger
from app.credentials import CredentialBroker
from app.gateway import ToolGateway
from app.identity import AgentRegistry
from app.supabase_store import SupabaseStore


# Shared runtime services. The Supabase adapter is optional for local tests and
# becomes active automatically when SUPABASE_URL and SUPABASE_SERVICE_KEY exist.
persistence = SupabaseStore.from_env()
agent_registry = AgentRegistry()
audit_ledger = AuditLedger(store=persistence)
credential_broker = CredentialBroker()
tool_gateway = ToolGateway(agent_registry, audit_ledger, credential_broker)
