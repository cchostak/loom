"""Assertions over real container execution, never a duplicate policy evaluator."""
import json
import time
import urllib.request

from runner import ROOT, call, compose, workflow

SCENARIOS = ("benign", "indirect", "escalation", "delegation", "exfiltration", "arguments", "runaway", "literal-injection", "tool-failure", "operator-denial")


def audit_records():
    result = call(compose(True) + ["exec", "-T", "control-plane", "cat", "/audit/security.jsonl"],
                  capture_output=True, text=True)
    return [json.loads(line) for line in result.stdout.splitlines()]


def no_bypass():
    """Inspect actual container mounts and attempt TCP/DNS access as a compromised interpreter."""
    config = json.loads(call(compose(True) + ["config", "--format", "json"],
                             capture_output=True, text=True).stdout)
    blocked = []
    for service, port in [("agentgateway", 3000), ("agentgateway", 8080),
                          ("guardrail-proxy", 9090), ("fixture-model", 8081),
                          ("presidio-analyzer", 5002)]:
        cid = call(compose(True) + ["ps", "-q", service], capture_output=True, text=True).stdout.strip()
        info = json.loads(call(["docker", "inspect", cid], capture_output=True, text=True).stdout)[0]
        blocked += [(v["IPAddress"], port) for v in info["NetworkSettings"]["Networks"].values()]
    blocked += [("1.1.1.1", 443), ("169.254.169.254", 80)]
    for role in ("researcher", "planner", "operator", "publisher"):
        service = config["services"]["strands-" + role]
        assert service["user"] == "65532:65532" and service["read_only"]
        assert service["cap_drop"] == ["ALL"]
        assert "no-new-privileges:true" in service["security_opt"]
        assert list(service["networks"]) == ["agents"]
        assert not service.get("volumes") and not service.get("ports")
        assert service["secrets"] == [{"source": "strands-" + role, "target": "loom_token"}]
    code = '''
import os, socket, pathlib, urllib.request
assert os.getuid() == 65532
for p in ['/var/run/docker.sock', '/bin/sh', '/usr/bin/bash', '/usr/bin/pip', '/workspace']:
    assert not pathlib.Path(p).exists(), p
assert len(list(pathlib.Path('/run/secrets').iterdir())) == 1
assert not any(k in os.environ for k in ['OPENAI_API_KEY','OPENROUTER_API_KEY','AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY','ANTHROPIC_API_KEY','HTTP_PROXY','HTTPS_PROXY'])
for host, port in BLOCKED:
    try:
        connection = socket.create_connection((host, port), timeout=0.3)
    except OSError:
        continue
    connection.close()
    raise AssertionError('direct network bypass')
try:
    socket.getaddrinfo('example.com',443)
except OSError:
    pass
else:
    raise AssertionError('external DNS forwarding enabled')
assert urllib.request.urlopen('http://control-plane:8080/health',timeout=5).status == 200
print('network and process isolation passed')
'''.replace("BLOCKED", repr(blocked))
    call(compose(True) + ["run", "--rm", "--no-deps", "-T", "--entrypoint", "/usr/bin/python3",
                          "strands-researcher", "-c", code])


    # Skip every Strands hook and forge identity/lineage claims. The opaque
    # planner credential still cannot acquire the researcher's read capability.
    probe = '''
import pathlib, httpx
headers = {"Authorization": "Bearer " + pathlib.Path("/run/secrets/loom_token").read_text(),
           "X-Agent-ID": "researcher", "X-Loom-Workload": "strands-researcher"}
body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
    "name": "read_text_file", "arguments": {"path": "/workspace/strands-evidence.txt"},
    "_meta": {"loom/provenance": {"trust": "trusted", "tainted": False}}}}
with httpx.Client(trust_env=False, follow_redirects=False) as client:
    response = client.post("http://control-plane:8080/mcp", headers=headers, json=body)
assert response.status_code == 403
assert response.headers.get("x-loom-decision-id")
print("hook-free identity and provenance spoof denied")
'''
    call(compose(True) + ["run", "--rm", "--no-deps", "-T", "--entrypoint", "/usr/bin/python3",
                          "strands-planner", "-c", probe])


def assert_scenario(result):
    events = result["events"]
    model = [e for e in events if e["category"] == "model" and e["stage"] == "response"]
    assert model and all(e["http_status"] == 200 for e in model), (result["scenario"], events)
    scenario = result["scenario"]
    if scenario == "benign":
        assert result["ok"]
        assert not any(e.get("status") == "rejected" for e in events)
    elif scenario == "tool-failure":
        assert any(e["stage"] == "tool_result" and e["status"] == "error" for e in events)
    elif scenario == "runaway":
        assert not result["ok"] and len(model) <= 6
        assert sum(e["stage"] == "tool_requested" for e in events) <= 4
    else:
        expected = 400 if scenario in ("arguments", "exfiltration", "delegation") else 403
        assert any(e["category"] == "mcp" and e.get("http_status") == expected
                   for e in events), (scenario, events)
    if scenario in ("benign", "indirect", "delegation", "exfiltration"):
        data = (result.get("handoff") or result["last_handoff"])["data"]
        assert data["tainted"] and data["trust"] == "untrusted"
        if scenario != "delegation":
            assert "mcp:filesystem" in data["parents"]
        assert "agent:" + ("planner" if scenario == "delegation" else "researcher") in [*data["parents"], data["source"]]
    assert all("content" not in e and "arguments" not in e for e in events)


def correlate(results):
    records = audit_records()
    # Match opaque server-generated IDs, not a fabricated client authorization event.
    wire = [e for r in results for e in r["events"] if e["stage"] == "response"]
    for event in wire:
        assert event.get("decision_id") and event.get("trace_id")
        matched = [r for r in records if r.get("trace_id") == event["trace_id"]]
        assert matched, event
        assert any(r["workload"] == "strands-" + event["agent"] for r in matched)
    closed = {r["trace_id"] for r in records
              if r["decision"]["rule_id"].endswith("session-delete")
              and r["stage"] == "result" and r["status"] < 400}
    runs = {(e["workflow"], e["agent"]) for e in wire}
    assert len(closed & {e["trace_id"] for e in wire}) == len(runs), "MCP session leak"
    # A successful MCP response is not necessarily a successful tool execution.
    assert any(e["stage"] == "tool_result" and e["status"] == "success"
               for r in results for e in r["events"])
    port = call(compose(True) + ["port", "jaeger", "16686"],
                capture_output=True, text=True).stdout.strip()
    trace_id = next(e["trace_id"] for e in wire if e["category"] == "model")
    for _ in range(15):
        try:
            with urllib.request.urlopen(f"http://{port}/api/traces/{trace_id}", timeout=3) as response:
                data = json.load(response)
                if data.get("data"):
                    return
        except OSError:
            pass
        time.sleep(1)
    raise AssertionError("No matching Agentgateway trace in Jaeger")


def run_lab():
    report = {"passed": False, "scenarios": []}
    destination = ROOT / "strands-report.json"
    destination.write_text(json.dumps(report, indent=2) + "\n")
    no_bypass()
    results = []
    for scenario in SCENARIOS:
        result = workflow(scenario, lab=True)
        item = {"scenario": scenario, "passed": False, "events": result["events"]}
        report["scenarios"].append(item)
        destination.write_text(json.dumps(report, indent=2) + "\n")
        assert_scenario(result)
        item["passed"] = True
        results.append(result)
        destination.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(item), flush=True)
    correlate(results)
    from tests.failures import failures
    failures()
    report.update(passed=True, audit_and_trace_correlated=True,
                  session_cleanup_verified=True, outages_verified=True, no_bypass_verified=True)
    destination.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": True, "scenarios": len(results), "audit_and_trace_correlated": True}), flush=True)
