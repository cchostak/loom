"""Local safety limits and tool lineage; not downstream authorization."""
import time

from strands.hooks import BeforeModelCallEvent, BeforeToolCallEvent, AfterToolCallEvent, HookProvider

from loom_strands.context import DataContext
from loom_strands.events import Events


class Limits(HookProvider):
    """Bound a single invocation and conservatively taint every tool result."""

    def __init__(self, events: Events, data: DataContext, connection=None):
        self.events, self.data = events, data
        self.connection = connection
        self.turns = self.tools = 0
        self.started = time.monotonic()

    def register_hooks(self, registry):
        registry.add_callback(BeforeModelCallEvent, self.before_model)
        registry.add_callback(BeforeToolCallEvent, self.before_tool)
        registry.add_callback(AfterToolCallEvent, self.after_tool)

    def check_time(self):
        if time.monotonic() - self.started > 90:
            raise RuntimeError("Local elapsed limit")

    def before_model(self, event):
        self.check_time()
        self.turns += 1
        if self.turns > 6:
            raise RuntimeError("Local model turn limit")
        self.events.emit("model_turn", "agent")

    def before_tool(self, event):
        self.check_time()
        self.tools += 1
        if self.tools > 4:
            raise RuntimeError("Local tool limit")
        if self.connection:
            self.connection.tool_data = None
        self.events.emit("tool_requested", "agent", tool=event.tool_use["name"])

    def after_tool(self, event):
        peer = self.connection.tool_data if self.connection else None
        derived = self.data.derived(self.events.role, "mcp:filesystem")
        if peer is not None:
            derived = DataContext(**dict(derived.model_dump(),
                sensitivity="sensitive" if "sensitive" in (peer.sensitivity, derived.sensitivity)
                else "unknown",
                parents=tuple(dict.fromkeys((*derived.parents, *peer.parents, peer.source)))))
        self.data = derived
        # Tool failures are explicit outcomes; no raw error text enters events.
        status = "success" if event.result.get("status") == "success" else "error"
        self.events.emit("tool_result", "agent", status=status, tool=event.tool_use["name"])
        if status == "error":
            raise RuntimeError("Tool failed; workflow stopped")
