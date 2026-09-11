from app.audit import AuditLedger
from app.credentials import CredentialBroker
from app.gateway import ToolGateway
from app.identity import AgentRegistry


# Shared runtime services. Keeping these in one module prevents API routers
# from accidentally creating isolated registries and security ledgers.
agent_registry = AgentRegistry()
audit_ledger = AuditLedger()
credential_broker = CredentialBroker()
tool_gateway = ToolGateway(agent_registry, audit_ledger, credential_broker)
