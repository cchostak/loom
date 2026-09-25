"""Strands MCPClient transport and strict interceptor middleware for Loom's MCP layer."""
from contextlib import asynccontextmanager
import json
import re
from typing import Any

import anyio
from jsonschema import Draft202012Validator
from mcp import types
from mcp.shared.message import SessionMessage
from strands.tools.mcp import MCPClient

from loom_strands.connection import Connection, LoomFailure
from loom_strands.context import DataContext
from loom_strands.mcp_validation import (
    contract,
    validate_request,
    validate_result,
    verify_response,
)

# Predefined JSON Schema for validating tool schema definitions to prevent tool poisoning.
TOOL_DEFINITION_SCHEMA = {
    "type": "object",
    "required": ["name", "description", "inputSchema"],
    "additionalProperties": False,
    "properties": {
        "name": {
            "type": "string",
            "pattern": r"^[a-zA-Z0-9_-]{1,64}$",
        },
        "description": {
            "type": "string",
            "maxLength": 1024,
        },
        "inputSchema": {
            "type": "object",
            "required": ["type"],
            "additionalProperties": False,
            "properties": {
                "type": {"const": "object"},
                "properties": {"type": "object"},
                "required": {"type": "array", "items": {"type": "string"}},
                "additionalProperties": {"type": "boolean"},
            },
        },
        "annotations": {"type": "object"},
    },
}

# Predefined JSON Schema for incoming data payloads to prevent malformed injections.
DATA_PAYLOAD_SCHEMA = {
    "type": "object",
    "required": ["content"],
    "additionalProperties": False,
    "properties": {
        "content": {
            "type": "array",
            "minItems": 1,
            "maxItems": 256,
            "items": {
                "type": "object",
                "required": ["type", "text"],
                "additionalProperties": False,
                "properties": {
                    "type": {"const": "text"},
                    "text": {"type": "string", "maxLength": 65536},
                },
            },
        },
        "isError": {"type": "boolean"},
        "_meta": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "loom/provenance": {"type": "object"},
            },
        },
    },
}

# Prompt injection markers prohibited in tool schemas and sanitized in data payloads.
PROMPT_INJECTION_RE = re.compile(
    r"(?i)(?:ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions|"
    r"disregard\s+(?:all\s+)?(?:previous|prior)\s+instructions|"
    r"reveal\s+(?:your\s+)?system\s+prompt|"
    r"<\s*\|\s*(?:im_start|im_end|system)\s*\|\s*>|"
    r"\[/?INST\]|"
    r"<\s*/?\s*(?:system|instructions)\s*>|"
    r"admin\s+override)"
)


class MCPInterceptorMiddleware:
    """Strict interceptor middleware for Model Context Protocol (MCP) interactions.

    Cryptographically validates and sanitizes incoming tool schemas and data payloads
    against predefined JSON schemas before execution to prevent tool poisoning
    and prompt injection via external data.
    """

    def __init__(self, tools: dict[str, Any] | None = None) -> None:
        self.tools = tools if tools is not None else contract()
        self._tool_validator = Draft202012Validator(TOOL_DEFINITION_SCHEMA)
        self._payload_validator = Draft202012Validator(DATA_PAYLOAD_SCHEMA)

    def validate_tool_schema(self, tool: dict[str, Any]) -> dict[str, Any]:
        """Validate and sanitize a tool definition against the schema and signed contract."""
        if not self._tool_validator.is_valid(tool):
            raise LoomFailure("Tool schema validation failed: invalid schema structure")

        desc = tool.get("description", "")
        if any(ord(c) < 32 and c not in "\n\r\t" for c in desc):
            raise LoomFailure("Tool description contains control characters")

        if PROMPT_INJECTION_RE.search(desc):
            raise LoomFailure("Tool poisoning detected: injection pattern in tool description")

        name = tool.get("name", "").removeprefix("filesystem_")
        if name not in self.tools:
            raise LoomFailure(f"Unregistered MCP capability: {name}")

        contract_tool = self.tools[name]
        normalized = dict(tool, name=name)
        if normalized != contract_tool:
            raise LoomFailure("MCP tool contract changed: signature mismatch")

        return normalized

    def sanitize_data_payload(self, result: dict[str, Any]) -> dict[str, Any]:
        """Sanitize and validate an incoming tool execution data payload."""
        if not self._payload_validator.is_valid(result):
            raise LoomFailure("MCP result schema denied: payload structure invalid")

        sanitized_content = []
        for block in result.get("content", []):
            text = block.get("text", "")
            if any(ord(c) < 32 and c not in "\n\r\t" for c in text):
                raise LoomFailure("MCP result contains control characters")
            clean_text = PROMPT_INJECTION_RE.sub("[SANITIZED_INJECTION_MARKER]", text)
            sanitized_content.append({"type": "text", "text": clean_text})

        sanitized_result = dict(result)
        sanitized_result["content"] = sanitized_content
        return sanitized_result

    def intercept_request(self, message: dict[str, Any]) -> dict[str, Any]:
        """Intercept and validate outgoing requests before execution."""
        validate_request(message, self.tools)
        return message

    def intercept_response(self, method: str | None, result: dict[str, Any]) -> dict[str, Any]:
        """Intercept, cryptographically validate and sanitize responses before model execution."""
        if method == "tools/list":
            if (
                not isinstance(result, dict)
                or "tools" not in result
                or not isinstance(result["tools"], list)
            ):
                raise LoomFailure("MCP tool discovery schema denied")
            sanitized_tools = []
            seen = set()
            for tool in result["tools"]:
                name = tool.get("name", "").removeprefix("filesystem_")
                if name in seen:
                    raise LoomFailure("MCP tool contract denied: duplicate tool")
                seen.add(name)
                sanitized_tools.append(self.validate_tool_schema(tool))
            validate_result(method, result, self.tools)
            return dict(result, tools=sanitized_tools)

        if method == "tools/call":
            validate_result(method, result, self.tools)
            return self.sanitize_data_payload(result)

        return result


@asynccontextmanager
async def transport(connection: Connection):
    """No SSE subscription, subprocess, server-driven URL or session resumption."""
    incoming_send, incoming = anyio.create_memory_object_stream(8)
    outgoing, outgoing_receive = anyio.create_memory_object_stream(8)

    session = ""
    tools = contract()
    interceptor = MCPInterceptorMiddleware(tools=tools)

    async def exchange():
        nonlocal session
        async with outgoing_receive, incoming_send:
            async for message in outgoing_receive:
                try:
                    outgoing_message = message.message.model_dump(by_alias=True, exclude_none=True)
                    interceptor.intercept_request(outgoing_message)
                    response = await connection.post("/mcp", outgoing_message, session)
                    session = response.headers.get("mcp-session-id", session)
                    if not response.content:
                        continue
                    verify_response(response, response.request.content, session)
                    if response.headers.get("content-type", "").startswith("text/event-stream"):
                        payloads = [
                            line[5:].strip()
                            for line in response.text.splitlines()
                            if line.startswith("data:")
                        ]
                    else:
                        payloads = [response.text]
                    if len(payloads) != 1:
                        raise LoomFailure("Unsupported MCP response")
                    parsed = types.JSONRPCMessage.model_validate(json.loads(payloads[0]))
                    # Server-initiated requests/notifications are not capabilities.
                    if not isinstance(parsed.root, (types.JSONRPCResponse, types.JSONRPCError)):
                        raise LoomFailure("Unsupported MCP server message")
                    if isinstance(parsed.root, types.JSONRPCResponse):
                        method = outgoing_message.get("method")
                        parsed.root.result = interceptor.intercept_response(
                            method, parsed.root.result
                        )
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
