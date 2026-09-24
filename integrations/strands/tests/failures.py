"""Reversible outages in the isolated lab, never in the developer project."""
import subprocess

from runner import call, compose, workflow


def failures():
    """No direct fallback when a provider/tool boundary disappears; telemetry is not policy."""
    for service, expected in (("fixture-model", False), ("agentgateway", False),
                              ("otel-collector", True)):
        call(compose(True) + ["stop", "-t", "1", service], stdout=subprocess.DEVNULL)
        try:
            result = workflow("benign", lab=True)
            assert result["ok"] is expected, (service, result["events"])
            if not expected:
                assert not any(e["stage"] == "tool_result" and e["status"] == "success"
                               for e in result["events"])
        finally:
            call(compose(True) + ["up", "-d", "--wait", "--wait-timeout", "120", service],
                 stdout=subprocess.DEVNULL)
