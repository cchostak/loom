#!/usr/bin/env python3
"""Real Compose ingress → Agentgateway → stdio MCP security regressions.

No provider call, destructive tool or external destination is used.
"""
import json
from pathlib import Path
import subprocess
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def request(url, body, token=None, session=None):
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    if token:
        headers["Authorization"] = "Bearer " + token
    if session:
        headers["Mcp-Session-Id"] = session
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=35) as response:
            data = response.read().decode()
            if data.startswith("event:") or data.startswith("data:"):
                data = next(line[5:].strip() for line in data.splitlines() if line.startswith("data:"))
            return response.status, json.loads(data) if data else {}, response.headers
    except urllib.error.HTTPError as error:
        return error.code, {}, error.headers


def run():
    """Exercise allowed reads and denied attacks through the running gateway."""
    port = subprocess.check_output(["docker", "compose", "port", "control-plane", "8080"], cwd=ROOT, text=True).splitlines()[0]
    url = "http://" + port + "/mcp"
    token = (ROOT / ".loom/client.token").read_text().strip()
    initialize = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    assert request(url, initialize)[0] == 401, "unauthenticated MCP allowed"
    assert request(url, initialize, "x" * 48)[0] == 401, "unknown credential allowed"
    status, body, headers = request(url, initialize, token)
    assert status == 200 and "result" in body, f"initialize failed: {status}"
    session = headers.get("Mcp-Session-Id")
    status, body, _ = request(url, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, token, session)
    assert status == 200 and "result" in body, f"discovery failed: {status}"
    names = [tool["name"] for tool in body["result"]["tools"]]
    assert len(names) == 2 and all(name.endswith(("read_text_file", "list_directory")) for name in names), "unexpected tool advertised"
    read = next(name for name in names if name.endswith("read_text_file"))
    fixture = ROOT / "workspace/loom-security-fixture.txt"
    link = ROOT / "workspace/loom-security-link"
    fixture_created = link_created = False
    try:
        with fixture.open("x") as file:
            file.write("Loom inert security fixture\n")
        fixture_created = True
        link.symlink_to("/etc/hostname")
        link_created = True
        cases = [
            (read, {"path": "/workspace/loom-security-fixture.txt"}, True),
            (read, {"path": "/workspace/../etc/hostname"}, False),
            (read, {"path": "/workspace/loom-security-link"}, False),
            (read, {"path": "/etc/hostname"}, False),
            (read, {"path": "/workspace/loom-security-fixture.txt", "command": "inert"}, False),
            ("write_file", {"path": "/workspace/unused"}, False),
            ("execute_command", {"path": "/workspace/unused"}, False),
            ("unknown", {"path": "/workspace/unused"}, False),
        ]
        for index, (name, arguments, allowed) in enumerate(cases, 3):
            call = {"jsonrpc": "2.0", "id": index, "method": "tools/call", "params": {"name": name, "arguments": arguments}}
            status, body, headers = request(url, call, token, session)
            success = status == 200 and "result" in body and not body["result"].get("isError")
            assert success == allowed, f"tool boundary failed case {index}: {status}"
            if allowed:
                assert "Loom inert security fixture" in json.dumps(body), "wrong file"
                assert headers.get("X-Loom-Decision-ID") and headers.get("X-Loom-Trace-ID"), "missing correlation"
        assert request(url, initialize, token, "invented-session")[0] == 403, "session spoof allowed"
    finally:
        if fixture_created:
            fixture.unlink()
        if link_created:
            link.unlink()
    print("PASS: authenticated real gateway discovery/read, unknown/write/exec/argument/traversal/symlink denial, session binding and decision correlation")


if __name__ == "__main__":
    run()
