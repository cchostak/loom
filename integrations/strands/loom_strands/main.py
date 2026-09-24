"""One-shot JSON worker. Only bounded validated handoffs are accepted on stdin."""
import json
import logging
import os
import sys

from opentelemetry import trace
from opentelemetry.trace import NoOpTracerProvider

from loom_strands.connection import Connection
from loom_strands.context import Handoff, ROLES
from loom_strands.events import Events
from loom_strands.runtime import invoke


def main() -> int:
    """Emit a result envelope without SDK logs or raw exception details."""
    logging.disable(logging.CRITICAL)
    trace.set_tracer_provider(NoOpTracerProvider())
    events = None
    try:
        role = os.environ["LOOM_AGENT_ROLE"]
        if role not in ROLES:
            raise ValueError("Unknown role")
        raw = sys.stdin.buffer.read(65537)
        if len(raw) > 65536:
            raise ValueError("Input limit")
        handoff = Handoff.model_validate_json(raw)
        events = Events(role, handoff.workflow, handoff.parent)
        result = invoke(role, handoff, Connection.from_secret(events))
        print(json.dumps({"ok": True, "handoff": result.model_dump(), "events": events.records}))
        return 0
    except Exception:
        print(json.dumps({"ok": False, "error": "Agent stopped safely",
                          "events": events.records if events else []}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
