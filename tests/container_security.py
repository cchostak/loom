#!/usr/bin/env python3
"""Check live Docker isolation settings without attempting destructive writes."""
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def run():
    ids = subprocess.check_output(["docker", "compose", "ps", "-q"], cwd=ROOT, text=True).split()
    assert ids, "no running Loom containers"
    inspected = json.loads(subprocess.check_output(["docker", "inspect", *ids], text=True))
    for container in inspected:
        name = container["Config"]["Labels"]["com.docker.compose.service"]
        user = container["Config"]["User"].split(":")[0]
        assert user not in ("", "0", "root"), f"root service: {name}"
        host = container["HostConfig"]
        assert not host["Privileged"], name
        assert "ALL" in host["CapDrop"], name
        assert "no-new-privileges:true" in host["SecurityOpt"], name
        assert host["Memory"] > 0 and host["PidsLimit"] > 0, name
        if name != "vscode":
            assert host["ReadonlyRootfs"], name
        for bindings in (host["PortBindings"] or {}).values():
            assert all(binding["HostIp"] == "127.0.0.1" for binding in bindings), name
        if name in ("agentgateway", "guardrail-proxy", "presidio-analyzer", "otel-collector"):
            assert not host["PortBindings"], name
        if name == "agentgateway":
            mount = next(m for m in container["Mounts"] if m["Destination"] == "/workspace")
            assert not mount["RW"], "writable MCP workspace"
    for executable in ("/bin/sh", "/usr/bin/npm", "/usr/bin/node"):
        result = subprocess.run(["docker", "compose", "exec", "-T", "agentgateway", executable, "--version"], cwd=ROOT, capture_output=True)
        assert result.returncode != 0 and b"no such file" in result.stdout + result.stderr, "unexpected runtime executable"
    print("PASS: live non-root containers, capability/privilege/resource bounds, loopback ports and read-only MCP mount; no Node/npm runtime")


if __name__ == "__main__":
    run()
