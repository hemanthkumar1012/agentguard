import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from fastapi.testclient import TestClient

from app.main import app
from app.mcp_remote import MCPServer, RemoteMCPClient
from app.services import agent_registry


class MCPHandler(BaseHTTPRequestHandler):
    request_body = None
    authorization = None

    def do_POST(self):
        length = int(self.headers["content-length"])
        MCPHandler.request_body = json.loads(self.rfile.read(length).decode())
        MCPHandler.authorization = self.headers.get("authorization")
        response = {"jsonrpc": "2.0", "id": MCPHandler.request_body["id"], "result": {"ok": True}}
        body = json.dumps(response).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


def test_remote_mcp_client_calls_json_rpc_server_with_token():
    server = ThreadingHTTPServer(("127.0.0.1", 0), MCPHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = RemoteMCPClient(MCPServer("local", f"http://127.0.0.1:{server.server_port}/mcp", "server-token"))
        assert client.call_tool("agt_demo", "lookup", {"id": "123"}) == {"ok": True}
        assert MCPHandler.authorization == "Bearer server-token"
        assert MCPHandler.request_body["method"] == "tools/call"
        assert MCPHandler.request_body["params"]["name"] == "lookup"
    finally:
        server.shutdown()


def test_mcp_endpoint_still_blocks_before_any_remote_execution():
    client = TestClient(app)
    agent = agent_registry.register("remote-mcp-agent", "security", permissions={"lookup"})
    response = client.post(
        "/api/v1/mcp/call",
        json={
            "agent_id": agent.agent_id,
            "tool": "unconfigured-remote",
            "action": "lookup",
            "target": "external-service",
            "arguments": {"id": "123"},
        },
    )
    assert response.status_code == 200
    assert response.json()["executed"] is False
    assert response.json()["decision"]["decision"] == "block"
    agent_registry._agents.pop(agent.agent_id, None)
