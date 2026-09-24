"""Real Strands event loop with transport fixtures; integration tests use containers."""
import asyncio
import json
import time
from types import SimpleNamespace

import httpx
import pytest
from strands import Agent

from loom_strands.connection import Connection, LoomFailure
from loom_strands.context import DataContext, Handoff
from loom_strands.events import Events
from loom_strands.hooks import Limits
from loom_strands.model import LoomModel


def connection(handler):
    return Connection("x" * 48, Events("planner", "a" * 32, "researcher"),
                      httpx.MockTransport(handler))


def completion(content):
    return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(content)}}]},
                          headers={"x-loom-trace-id": "b" * 32, "x-loom-decision-id": "c" * 32})


def test_actual_strands_model_loop():
    requests = []

    def handle(request):
        requests.append(request)
        return completion({"text": "A bounded plan"})

    conn = connection(handle)
    result = Agent(model=LoomModel(conn), callback_handler=None, retry_strategy=None)("Plan")
    assert str(result).strip() == "A bounded plan"
    assert len(requests) == 1
    assert str(requests[0].url) == "http://control-plane:8080/v1/chat/completions"
    assert requests[0].headers["authorization"] == "Bearer " + "x" * 48
    assert conn.events.records[-1]["decision_id"] == "c" * 32


@pytest.mark.parametrize("status", [301, 400, 401, 403, 429, 500, 502, 503, 504])
def test_no_fallback(status):
    seen = []

    def handle(request):
        seen.append(request)
        return httpx.Response(status, headers={"location": "https://provider.invalid"})

    conn = connection(handle)
    with pytest.raises(LoomFailure):
        asyncio.run(conn.post("/v1/chat/completions", {}))
    assert len(seen) == 1
    assert conn.events.records[-1]["status"] == "rejected"


@pytest.mark.parametrize("error", [httpx.ConnectError, httpx.ReadTimeout, httpx.RemoteProtocolError])
def test_unavailable(error):
    def handle(request):
        raise error("sensitive upstream detail")

    conn = connection(handle)
    with pytest.raises(LoomFailure, match="^Loom unavailable$"):
        asyncio.run(conn.post("/mcp", {}))
    assert "sensitive" not in json.dumps(conn.events.records)


@pytest.mark.parametrize("action", [None, [], {"text": 1}, {"tool": "a", "input": []},
                                    {"text": "a", "url": "https://evil.invalid"}])
def test_malformed_model(action):
    async def run():
        return [event async for event in LoomModel(connection(lambda _: completion(action))).stream([])]
    with pytest.raises(LoomFailure):
        asyncio.run(run())


@pytest.mark.parametrize("origin", ["user", "external", "repository", "tool", "model", "derived"])
def test_lineage_survives_handoff(origin):
    data = DataContext(source="document", origin=origin, sensitivity="sensitive")
    h = Handoff(workflow="a" * 32, content="Untrusted evidence", data=data)
    h = h.next("researcher", "summary").next("planner", "plan")
    assert h.data.tainted and h.data.trust == "untrusted"
    assert h.data.sensitivity == "sensitive"
    assert h.data.parents == ("document", "agent:researcher")


@pytest.mark.parametrize("change", [{"trust": "trusted"}, {"tainted": False},
                                     {"integrity": "forged"}, {"parents": ["x"] * 17}])
def test_cannot_upgrade_lineage(change):
    with pytest.raises(ValueError):
        DataContext(**change)


def test_limits_and_events():
    e = Events("planner", "a" * 32, "researcher")
    limit = Limits(e, DataContext())
    for _ in range(6):
        limit.before_model(None)
    with pytest.raises(RuntimeError):
        limit.before_model(None)
    for _ in range(4):
        limit.before_tool(SimpleNamespace(tool_use={"name": "request_capability"}))
    with pytest.raises(RuntimeError):
        limit.before_tool(SimpleNamespace(tool_use={"name": "request_capability"}))
    with pytest.raises(RuntimeError, match="workflow stopped"):
        limit.after_tool(SimpleNamespace(result={"status": "error", "secret": "DO_NOT_LOG"},
                                         tool_use={"name": "request_capability"}))
    assert limit.data.source == "mcp:filesystem"
    assert "DO_NOT_LOG" not in json.dumps(e.records)
    limit.started = time.monotonic() - 91
    with pytest.raises(RuntimeError):
        limit.check_time()


def test_handoff_bounds():
    with pytest.raises(ValueError):
        Handoff(workflow="a" * 32, content="x", depth=4).next("planner", "done")
    with pytest.raises(ValueError):
        Handoff(workflow="a" * 32, content="x" * 16001)


def test_telemetry_capacity_fails_closed():
    e = Events("planner", "a" * 32, "user")
    for _ in range(256):
        e.emit("requested", "model")
    with pytest.raises(RuntimeError):
        e.emit("requested", "model")


def test_input_and_output_caps():
    conn = connection(lambda _: httpx.Response(200, content=b"x" * ((1 << 20) + 1)))
    with pytest.raises(LoomFailure, match="input limit"):
        asyncio.run(conn.post("/mcp", {"value": "x" * 65536}))
    with pytest.raises(LoomFailure, match="output limit"):
        asyncio.run(conn.post("/mcp", {}))


def test_fixed_model_and_routes():
    conn = connection(lambda _: completion({"text": "ok"}))
    with pytest.raises(LoomFailure):
        asyncio.run(conn.post("https://provider.invalid", {}))
    with pytest.raises(LoomFailure):
        LoomModel(conn).update_config(base_url="https://provider.invalid")


def test_tool_provenance_merges_without_lowering_sensitivity():
    event = SimpleNamespace(result={"status": "success"}, tool_use={"name": "read_text_file"})
    conn = connection(lambda _: completion({"text": "ok"}))
    conn.tool_data = DataContext(source="workspace", producer="loom-readonly-filesystem",
                                 origin="tool", sensitivity="sensitive")
    limits = Limits(conn.events, DataContext(source="external"), conn)
    limits.after_tool(event)
    assert limits.data.sensitivity == "sensitive"
    assert "workspace" in limits.data.parents and "external" in limits.data.parents
    conn.tool_data = DataContext(source="workspace", origin="tool")
    limits.after_tool(event)
    assert limits.data.sensitivity == "sensitive" and limits.data.tainted


def test_opaque_metadata_is_not_model_content():
    requests = []
    def handle(request):
        requests.append(json.loads(request.content))
        return completion({"text": "ok"})
    conn = connection(handle)
    async def run():
        return [e async for e in LoomModel(conn).stream([
            {"role": "user", "content": [{"text": "evidence"}]}])]
    asyncio.run(run())
    assert requests[0]["messages"][1]["content"] == "evidence"
    assert "a" * 32 not in json.dumps(requests)
