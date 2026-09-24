"""Content-free lifecycle records; core Loom audit remains authoritative."""
import re
import threading


class Events:
    """Bounded in-memory records emitted only by the process entrypoint."""

    def __init__(self, role: str, workflow: str, parent: str):
        self.role, self.workflow, self.parent = role, workflow, parent
        self.records: list[dict] = []
        self.lock = threading.Lock()

    def emit(self, stage: str, category: str, *, response=None, status: str = "", tool: str = "") -> None:
        """Only fixed fields and validated opaque correlation IDs leave the runtime."""
        record = dict(agent=self.role, workflow=self.workflow, parent=self.parent,
                      stage=stage, category=category, status=status,
                      trust="untrusted", tainted=True)
        if tool:
            record["tool"] = tool if tool in {
                "request_capability", "read_text_file", "list_directory",
                "filesystem_read_text_file", "filesystem_list_directory",
            } else "unregistered"
        if response is not None:
            record["http_status"] = response.status_code
            for header, field in (("x-loom-trace-id", "trace_id"),
                                  ("x-loom-decision-id", "decision_id")):
                value = response.headers.get(header, "")
                if re.fullmatch(r"[a-f0-9]{32}", value):
                    record[field] = value
        with self.lock:
            if len(self.records) >= 256:
                raise RuntimeError("Local event capacity exceeded")
            self.records.append(record)
