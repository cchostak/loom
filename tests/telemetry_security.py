#!/usr/bin/env python3
"""Verify known sensitive OTLP fields are removed by the real collector."""
import json
from pathlib import Path
import secrets
import subprocess
import time
import urllib.request
import urllib.error

ROOT = Path(__file__).resolve().parents[1]


def run():
    trace = secrets.token_hex(16)
    marker = "synthetic-secret-must-not-export"
    attribute = {"key": "authorization", "value": {"stringValue": marker}}
    now = time.time_ns()
    payload = {"resourceSpans": [{
        "resource": {"attributes": [attribute]},
        "scopeSpans": [{
            "scope": {"name": marker, "version": marker, "attributes": [attribute]},
            "spans": [{
                "traceId": trace, "spanId": secrets.token_hex(8), "name": marker,
                "startTimeUnixNano": str(now), "endTimeUnixNano": str(now + 1000000),
                "attributes": [attribute], "status": {"code": 2, "message": marker},
                "traceState": "secret=" + marker,
                "events": [{"timeUnixNano": str(now), "name": marker, "attributes": [attribute]}],
                "links": [{"traceId": secrets.token_hex(16), "spanId": secrets.token_hex(8), "attributes": [attribute]}],
            }],
        }],
    }]}
    subprocess.run([
        "docker", "compose", "exec", "-T", "guardrail-proxy", "curl", "-fsS",
        "http://otel-collector:4318/v1/traces", "-H", "Content-Type: application/json",
        "--data-binary", "@-",
    ], input=json.dumps(payload), text=True, capture_output=True, check=True, cwd=ROOT)
    port = subprocess.check_output(["docker", "compose", "port", "jaeger", "16686"], cwd=ROOT, text=True).strip()
    for _ in range(15):
        try:
            with urllib.request.urlopen("http://" + port + "/api/traces/" + trace, timeout=5) as response:
                raw = response.read().decode()
        except urllib.error.HTTPError as error:
            if error.code != 404:
                raise
            time.sleep(1)
            continue
        data = json.loads(raw)
        if data.get("data"):
            assert marker not in raw, "sensitive OTLP field exported"
            assert trace in raw, "trace correlation lost"
            print("PASS: real collector suppresses span/resource/scope/event/link/status/trace-state secrets and preserves trace ID")
            return
        time.sleep(1)
    raise AssertionError("trace did not reach Jaeger")


if __name__ == "__main__":
    run()
