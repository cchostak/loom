"""Credential separation, idempotency and fail-closed handoff orchestration."""
import hashlib
import importlib.util
import json
import subprocess
from unittest.mock import patch

import pytest

from runner import ROOT, worker

spec = importlib.util.spec_from_file_location("bootstrap_strands", ROOT / "scripts/bootstrap_strands.py")
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)


def registry(root):
    folder = root / ".loom/identity"
    folder.mkdir(parents=True)
    path = folder / "credentials.json"
    path.write_text('[{"identity":{"workload":"local-agent"},"sha256":"original"}]')
    return path


def test_credentials_separate_idempotent(tmp_path):
    path = registry(tmp_path)
    bootstrap.provision(tmp_path)
    original = path.read_bytes()
    bootstrap.provision(tmp_path)
    assert path.read_bytes() == original
    records = json.loads(original)
    assert records[0]["sha256"] == "original"
    assert len({r["sha256"] for r in records}) == 5
    assert (tmp_path / ".loom/strands").stat().st_mode & 0o777 == 0o700
    for role in bootstrap.ROLES:
        token = (tmp_path / f".loom/strands/{role}.token").read_bytes()
        record = next(r for r in records if r["sha256"] == hashlib.sha256(token).hexdigest())
        identity = record["identity"]
        assert identity["workload"] == "strands-" + role
        if role in ("planner", "publisher"):
            assert identity["scopes"] == ["model:invoke", "mcp:connect"]


def test_partial_provisioning_refused(tmp_path):
    registry(tmp_path)
    (tmp_path / ".loom/strands").mkdir()
    (tmp_path / ".loom/strands/researcher.token").write_text("incomplete")
    with pytest.raises(RuntimeError):
        bootstrap.provision(tmp_path)


def test_mismatched_token_refused(tmp_path):
    registry(tmp_path)
    bootstrap.provision(tmp_path)
    path = tmp_path / ".loom/strands/researcher.token"
    path.chmod(0o600)
    path.write_text("mismatch")
    with pytest.raises(RuntimeError):
        bootstrap.provision(tmp_path)


@pytest.mark.parametrize("stdout,code", [("", 137), ('{"ok":true}', 1), ("{}", 0), ("[]", 0)])
def test_crash_never_commits_handoff(stdout, code):
    with patch("runner.subprocess.run", return_value=subprocess.CompletedProcess([], code, stdout)) as run:
        with pytest.raises(RuntimeError, match="handoff aborted"):
            worker("planner", {"content": "x"}, lab=True)
        assert run.call_args_list[-1].args[0][:3] == ["docker", "rm", "-f"]


def test_timeout_removes_worker():
    with patch("runner.subprocess.run", side_effect=[subprocess.TimeoutExpired("compose", 120), None]) as run:
        with pytest.raises(RuntimeError, match="timeout"):
            worker("planner", {}, lab=True)
        assert run.call_args_list[-1].args[0][:3] == ["docker", "rm", "-f"]


def test_unknown_role_cannot_inject_compose_arguments():
    with pytest.raises(ValueError):
        worker("--privileged", {}, lab=True)
