#!/usr/bin/env python3
"""Add isolated role credentials without rotating existing developer identities."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import secrets
import tempfile

ROLES = ("researcher", "planner", "operator", "publisher")


def provision(root: Path) -> None:
    """Idempotent provisioning; inconsistent state is an error, never an implicit reset."""
    base = root / ".loom"
    registry = base / "identity/credentials.json"
    records = json.loads(registry.read_text())
    target = base / "strands"
    target.mkdir(mode=0o700, exist_ok=True)
    existing = [r for r in records if r["identity"]["workload"].startswith("strands-")]
    if existing or any(target.iterdir()):
        if len(existing) != 4:
            raise RuntimeError("Partial Strands provisioning; restore credentials and registry")
        for role in ROLES:
            digest = hashlib.sha256((target / f"{role}.token").read_bytes()).hexdigest()
            if not any(r["sha256"] == digest and r["identity"]["workload"] == f"strands-{role}"
                       for r in existing):
                raise RuntimeError("Strands credential mismatch")
        return
    expiry = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=7)).isoformat()
    for role in ROLES:
        token = secrets.token_urlsafe(48)
        path = target / f"{role}.token"
        # Parent is 0700; projected secret must be readable by container UID 65532.
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444), "w") as out:
            out.write(token)
        scopes = ["model:invoke", "mcp:connect"]
        if role == "researcher":
            scopes.append("workspace:read")
        if role == "operator":
            scopes.append("workspace:list")
        records.append(dict(sha256=hashlib.sha256(token.encode()).hexdigest(),
                            audience="loom-local", expires=expiry, identity=dict(
                                principal="local-developer", workload=f"strands-{role}",
                                tenant="local", session=secrets.token_hex(16),
                                authentication="local-opaque-bearer", scopes=scopes)))
    with tempfile.NamedTemporaryFile(mode="w", dir=registry.parent, delete=False) as out:
        json.dump(records, out, indent=2)
        out.write("\n")
        os.fchmod(out.fileno(), 0o644)
        os.fsync(out.fileno())
    os.replace(out.name, registry)


if __name__ == "__main__":
    provision(Path(__file__).resolve().parents[1])
    print("Strands role credentials ready (seven-day local credentials).")
