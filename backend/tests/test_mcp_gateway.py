from app.api.tools import runtime
from app.mcp_gateway import MCPGateway, MCPToolRequest
from app.services import agent_registry, credential_broker


def test_mcp_gateway_blocks_without_scoped_credential():
    agent = agent_registry.register("mcp-demo", "test", permissions={"echo"})
    result = MCPGateway(runtime).call(MCPToolRequest(
        agent_id=agent.agent_id, tool="demo", action="echo", target="demo", arguments={"message": "hello"}
    ))
    assert result["executed"] is False
    assert result["decision"]["decision"] == "block"
    agent_registry._agents.pop(agent.agent_id, None)


def test_mcp_gateway_executes_after_authorization():
    agent = agent_registry.register("mcp-demo", "test", permissions={"echo"})
    credential = credential_broker.issue(agent.agent_id, "demo", {"echo"})
    result = MCPGateway(runtime).call(MCPToolRequest(
        agent_id=agent.agent_id, tool="demo", action="echo", target="demo", arguments={"message": "hello"},
        credential_id=credential.credential_id, credential_token=credential.token,
    ))
    assert result["executed"] is True
    assert result["result"]["status"] == "executed"
    agent_registry._agents.pop(agent.agent_id, None)
