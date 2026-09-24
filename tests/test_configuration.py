"""Static invariants, distinct from runtime isolation evidence."""
import json
import os
from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ConfigurationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        result = subprocess.run(
            ["docker", "compose", "config", "--format", "json"], cwd=ROOT,
            env=dict(os.environ, IDE_PASSWORD="configuration-test-only"),
            check=True, capture_output=True, text=True,
        )
        cls.config = json.loads(result.stdout)

    def test_loopback_only(self):
        for name, service in self.config["services"].items():
            for port in service.get("ports", []):
                self.assertEqual(port.get("host_ip"), "127.0.0.1", name)

    def test_internal_services_unpublished(self):
        for name in ("agentgateway", "guardrail-proxy", "otel-collector", "presidio-analyzer"):
            self.assertFalse(self.config["services"][name].get("ports"), name)

    def test_no_ide_gateway_network(self):
        services = self.config["services"]
        self.assertFalse(set(services["vscode"]["networks"]) & set(services["agentgateway"]["networks"]))

    def test_container_privilege(self):
        for name, service in self.config["services"].items():
            self.assertIn("ALL", service["cap_drop"], name)
            self.assertIn("no-new-privileges:true", service["security_opt"], name)
            self.assertGreater(service["pids_limit"], 0, name)
            self.assertGreater(int(service["mem_limit"]), 0, name)
            if name != "vscode":
                self.assertTrue(service["read_only"], name)

    def test_workspace_readonly(self):
        mounts = self.config["services"]["agentgateway"]["volumes"]
        self.assertTrue(next(v for v in mounts if v["target"] == "/workspace")["read_only"])
        self.assertNotIn("SUDO_PASSWORD", self.config["services"]["vscode"].get("environment", {}))

    def test_no_runtime_package_execution(self):
        config = (ROOT / "config/agentgateway-config.yaml").read_text()
        self.assertNotIn("npx", config)
        self.assertIn('args: ["--isolated"]', config)
        for name in ("gateway", "guardrail", "control", "lab"):
            self.assertIn("USER 65532:65532", (ROOT / f"docker/Dockerfile.{name}").read_text())

    def test_immutable_actions_and_enforced_scans(self):
        for file in (ROOT / ".github/workflows").glob("*.yml"):
            for ref in re.findall(r"uses:\s+([^\s]+)", file.read_text()):
                self.assertRegex(ref, r"@[0-9a-f]{40}$")
            self.assertNotIn("pull_request_target", file.read_text())
        text = (ROOT / ".github/workflows/security.yml").read_text()
        self.assertNotIn("exit-code: '0'", text)
        for value in ("sbom: true", "provenance: mode=max", "scan-type: image", "fail-on-severity: high"):
            self.assertIn(value, text)

    def test_telemetry_suppression(self):
        text = (ROOT / "config/otel-collector-config.yaml").read_text()
        self.assertNotIn("exporters: [debug]", text)
        self.assertIn("keep_keys(attributes, [])", text)
        self.assertIn('set(status.message, "")', text)
        self.assertIn("transform/privacy", text)
