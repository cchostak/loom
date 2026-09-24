"""Exercise the actual Strands MCP session against controlled HTTP failures."""
import json

import httpx
import pytest

from loom_strands.connection import Connection
from loom_strands.events import Events
from loom_strands.mcp import client


def test_mcp_client_uses_authenticated_post_and_bound_session():
    seen = []

    def handle(request):
        seen.append(request)
        data = json.loads(request.content)
        method = data["method"]
        if method == "notifications/initialized":
            return httpx.Response(202)
        result = {"protocolVersion": "2025-03-26", "capabilities": {"tools": {}},
                  "serverInfo": {"name": "fixture", "version": "1"}}
        if method == "tools/list":
            result = {"tools": []}
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": data["id"], "result": result},
                              headers={"Mcp-Session-Id": "bound-session"})

    conn = Connection("x" * 48, Events("planner", "a" * 32, "user"), httpx.MockTransport(handle))
    with client(conn) as mcp:
        assert list(mcp.list_tools_sync()) == []
    assert all(r.method == "POST" and r.url.path == "/mcp" for r in seen)
    assert seen[-1].headers["Mcp-Session-Id"] == "bound-session"
    assert all(r.headers["authorization"] == "Bearer " + "x" * 48 for r in seen)


@pytest.mark.parametrize("response", [httpx.Response(403), httpx.Response(503),
                                     httpx.Response(200, json={"bogus": True}),
                                     httpx.Response(200, json={"jsonrpc": "2.0", "id": 1,
                                                              "method": "sampling/createMessage"})])
def test_mcp_failure_cannot_start_agent(response):
    seen = []

    def handle(request):
        seen.append(request)
        return response

    conn = Connection("x" * 48, Events("planner", "a" * 32, "user"), httpx.MockTransport(handle))
    with pytest.raises(Exception):
        with client(conn):
            pytest.fail("MCP startup should fail")
    assert len(seen) == 1
