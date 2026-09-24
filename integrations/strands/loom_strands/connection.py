"""Single fixed authenticated HTTP destination; no redirects, proxies or fallback."""
from pathlib import Path

import httpx

from loom_strands.events import Events

BASE_URL = "http://control-plane:8080"
MODEL = "openai/gpt-4o-mini"


class LoomFailure(RuntimeError):
    """A security or availability failure with no sensitive upstream body."""


class Connection:
    """Transport shared by the model and MCP adapters."""

    def __init__(self, token: str, events: Events, transport=None):
        if len(token) < 32 or any(c.isspace() for c in token):
            raise ValueError("Invalid Loom credential")
        self.token, self.events, self.transport = token, events, transport

    @classmethod
    def from_secret(cls, events: Events) -> "Connection":
        """Read only the role-specific Compose secret."""
        return cls(Path("/run/secrets/loom_token").read_text().strip(), events)

    async def post(self, path: str, payload: dict, session: str = "") -> httpx.Response:
        """Bound requests/results and surface denial without interpreting it as approval."""
        if path not in ("/mcp", "/v1/chat/completions"):
            raise LoomFailure("Unsupported Loom route")
        import json
        body = json.dumps(payload).encode()
        if len(body) > 65536:
            raise LoomFailure("Local input limit")
        category = "mcp" if path == "/mcp" else "model"
        self.events.emit("requested", category)
        headers = {"Authorization": "Bearer " + self.token,
                   "Content-Type": "application/json",
                   "Accept": "application/json, text/event-stream"}
        if session:
            headers["Mcp-Session-Id"] = session
        try:
            async with httpx.AsyncClient(timeout=35, trust_env=False, follow_redirects=False,
                                         transport=self.transport) as client:
                async with client.stream("POST", BASE_URL + path, content=body,
                                         headers=headers) as response:
                    chunks = bytearray()
                    async for chunk in response.aiter_bytes():
                        chunks.extend(chunk)
                        if len(chunks) > 1 << 20:
                            raise LoomFailure("Local output limit")
                    result = httpx.Response(response.status_code, headers=response.headers,
                                            content=bytes(chunks))
        except httpx.HTTPError:
            self.events.emit("failed", category, status="unavailable")
            raise LoomFailure("Loom unavailable") from None
        self.events.emit("response", category, response=result,
                         status="accepted" if result.is_success else "rejected")
        if not result.is_success:
            # Approval and transform have no production protocol yet; never auto-confirm.
            raise LoomFailure("Loom rejected request")
        return result
