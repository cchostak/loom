"""Strands MCPClient transport for Loom's bounded MCP request and teardown subset."""
from contextlib import asynccontextmanager
import json

import anyio
from mcp import types
from mcp.shared.message import SessionMessage
from strands.tools.mcp import MCPClient

from loom_strands.connection import Connection, LoomFailure
from loom_strands.context import DataContext


@asynccontextmanager
async def transport(connection: Connection):
    """No SSE subscription, subprocess, server-driven URL or session resumption."""
    incoming_send, incoming = anyio.create_memory_object_stream(8)
    outgoing, outgoing_receive = anyio.create_memory_object_stream(8)

    session = ""

    async def exchange():
        nonlocal session
        async with outgoing_receive, incoming_send:
            async for message in outgoing_receive:
                try:
                    response = await connection.post(
                        "/mcp", message.message.model_dump(by_alias=True, exclude_none=True), session)
                    session = response.headers.get("mcp-session-id", session)
                    if not response.content:
                        continue
                    if response.headers.get("content-type", "").startswith("text/event-stream"):
                        payloads = [line[5:].strip() for line in response.text.splitlines()
                                    if line.startswith("data:")]
                    else:
                        payloads = [response.text]
                    if len(payloads) != 1:
                        raise LoomFailure("Unsupported MCP response")
                    parsed = types.JSONRPCMessage.model_validate(json.loads(payloads[0]))
                    # Server-initiated requests/notifications are not capabilities.
                    if not isinstance(parsed.root, (types.JSONRPCResponse, types.JSONRPCError)):
                        raise LoomFailure("Unsupported MCP server message")
                    if isinstance(parsed.root, types.JSONRPCResponse):
                        metadata = parsed.root.result.get("_meta", {}).get("loom/provenance")
                        if metadata is not None:
                            connection.tool_data = DataContext.model_validate(metadata)
                    await incoming_send.send(SessionMessage(parsed))
                except Exception:
                    await incoming_send.send(LoomFailure("MCP exchange failed"))
                    return

    async with anyio.create_task_group() as group:
        group.start_soon(exchange)
        try:
            yield incoming, outgoing
        finally:
            group.cancel_scope.cancel()
            await incoming.aclose()
            await outgoing.aclose()
            # An owned DELETE closes Agentgateway's per-session stdio child.
            # Shield teardown from task-group cancellation, but bound it to 5s.
            with anyio.CancelScope(shield=True):
                await connection.close_session(session)


def client(connection: Connection) -> MCPClient:
    """Use the real Strands MCP session and tool adapter, with fail-closed startup."""
    return MCPClient(lambda: transport(connection), startup_timeout=15)
