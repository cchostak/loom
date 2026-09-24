#!/usr/bin/env python3
"""Provision a local opaque credential without printing its value."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import secrets


def bootstrap(root: Path) -> None:
    """Create idempotent local identity files; refuse partial provisioning."""
    base = root / ".loom"
    identity = base / "identity"
    identity.mkdir(parents=True, exist_ok=True)
    base.chmod(0o700)
    token_path = base / "client.token"
    registry = identity / "credentials.json"
    if token_path.exists() or registry.exists():
        if not token_path.is_file() or not registry.is_file():
            raise RuntimeError("Partial identity setup; restore both identity files")
        return
    token = secrets.token_urlsafe(48)
    with os.fdopen(os.open(token_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as out:
        out.write(token)
    record = [{
        "sha256": hashlib.sha256(token.encode()).hexdigest(),
        "audience": "loom-local",
        "expires": (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=7)).isoformat(),
        "identity": {
            "principal": "local-developer", "workload": "local-agent", "tenant": "local",
            "session": secrets.token_hex(16), "authentication": "local-opaque-bearer",
            "scopes": ["workspace:read", "model:invoke"],
        },
    }]
    pipeline_token = secrets.token_urlsafe(48)
    pipeline_path = base / "pipeline.token"
    with os.fdopen(os.open(pipeline_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444), "w") as out:
        out.write(pipeline_token)
    pipeline_identity = dict(record[0]["identity"], workload="pipeline", session=secrets.token_hex(16), scopes=["model:invoke"])
    record.append(dict(record[0], sha256=hashlib.sha256(pipeline_token.encode()).hexdigest(), identity=pipeline_identity))
    registry.write_text(json.dumps(record, indent=2) + "\n")
    registry.chmod(0o644)  # Hashes only; available to the unprivileged container.


if __name__ == "__main__":
    bootstrap(Path(__file__).resolve().parents[1])
    print("Local credential ready in .loom/client.token (expires after 7 days).")
