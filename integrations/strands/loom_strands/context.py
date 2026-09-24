"""Untrusted lineage compatible with Go security.DataContext."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

ROLES = ("researcher", "planner", "operator", "publisher")


class DataContext(BaseModel):
    """Descriptive lineage, never an authorization claim."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    source: str = Field(default="user", max_length=128)
    producer: str = Field(default="user", max_length=64)
    trust: Literal["untrusted"] = "untrusted"
    sensitivity: Literal["unknown", "sensitive"] = "unknown"
    origin: Literal["user", "tool", "model", "derived", "repository", "external"] = "user"
    tainted: Literal[True] = True
    integrity: Literal[""] = ""
    parents: tuple[str, ...] = Field(default=(), max_length=16)

    def derived(self, producer: str, source: str) -> "DataContext":
        """Preserve classification while adding a bounded parent relationship."""
        return DataContext(
            source=source, producer=producer, sensitivity=self.sensitivity,
            origin="derived", parents=(*self.parents, self.source),
        )


class Handoff(BaseModel):
    """Validated process-to-process message; no privileged serialized objects."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    workflow: str = Field(pattern=r"^[a-f0-9]{32}$")
    parent: Literal["user", "researcher", "planner", "operator", "publisher"] = "user"
    depth: int = Field(default=0, ge=0, le=4)
    content: str = Field(min_length=1, max_length=16000)
    data: DataContext = Field(default_factory=DataContext)

    def next(self, role: str, content: str) -> "Handoff":
        """Commit a complete handoff; never synthesize success after a crash."""
        return Handoff(workflow=self.workflow, parent=role, depth=self.depth + 1,
                       content=content, data=self.data.derived(role, f"agent:{role}"))
