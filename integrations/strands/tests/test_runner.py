"""Host-run evidence must not reuse an earlier successful report."""
import fcntl
import json
import sys
from unittest.mock import Mock

import pytest

import runner


def test_failed_start_invalidates_previous_success(tmp_path, monkeypatch):
    report = tmp_path / "strands-report.json"
    report.write_text('{"passed": true}')
    monkeypatch.setattr(runner, "ROOT", tmp_path)
    monkeypatch.setattr(sys, "argv", ["runner", "lab"])
    monkeypatch.setattr(runner, "start", Mock(side_effect=RuntimeError("startup failed")))
    with pytest.raises(RuntimeError, match="startup failed"):
        runner.main()
    assert json.loads(report.read_text()) == {"passed": False, "scenarios": []}


def test_concurrent_runner_cannot_renew_active_credentials(tmp_path, monkeypatch):
    state = tmp_path / ".loom"
    state.mkdir()
    start = Mock()
    monkeypatch.setattr(runner, "ROOT", tmp_path)
    monkeypatch.setattr(sys, "argv", ["runner", "lab"])
    monkeypatch.setattr(runner, "start", start)
    with (state / "strands-run.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(BlockingIOError):
            runner.main()
    start.assert_not_called()
    assert not (tmp_path / "strands-report.json").exists()
