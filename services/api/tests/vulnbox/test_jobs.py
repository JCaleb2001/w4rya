"""Background jobs: one at a time across workers, results kept per kind, and
a job whose worker died reported as interrupted (decided by the lock, not by
guessing from timestamps)."""

import json
import os
import threading
import time

import pytest

from vulnbox import config as vconfig
from vulnbox import jobs


def wait_idle(timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        cur = jobs.snapshot()["current"]
        if cur and cur["state"] != "running":
            return cur
        time.sleep(0.01)
    raise AssertionError("job did not finish")


def test_job_runs_in_background_and_keeps_its_result(vbox_dir):
    rec = jobs.start("recon", lambda: {"services": [1, 2]}, actor="alice")
    assert rec["state"] == "running"
    assert rec["kind"] == "recon" and rec["started_by"] == "alice"
    done = wait_idle()
    assert done["state"] == "done"
    assert done["result"] == {"services": [1, 2]}
    assert jobs.snapshot()["last"]["recon"]["state"] == "done"


def test_second_start_while_running_is_refused(vbox_dir):
    gate = threading.Event()
    jobs.start("backup", lambda: gate.wait(5) or {}, actor="a")
    with pytest.raises(jobs.JobBusy) as exc:
        jobs.start("recon", lambda: {}, actor="b")
    assert exc.value.kind == "backup"
    gate.set()
    wait_idle()
    # lock released afterwards: a new job can start
    jobs.start("recon", lambda: {}, actor="b")
    wait_idle()


def test_failure_is_recorded_with_its_message(vbox_dir):
    def boom():
        raise RuntimeError("cannot reach the vulnbox — is the game VPN up?")
    jobs.start("preflight", boom, actor="a")
    done = wait_idle()
    assert done["state"] == "error"
    assert "VPN" in done["error"]


def test_dead_worker_reads_as_interrupted(vbox_dir):
    # A "running" record with nobody holding the lock = the worker died.
    stale = {"id": "x", "kind": "backup", "state": "running", "started_by": "a",
             "started_at": "2000-01-01T00:00:00+00:00", "finished_at": None,
             "result": None, "error": None}
    vconfig.job_path().write_text(json.dumps({"current": stale, "last": {}}))
    snap = jobs.snapshot()
    assert snap["current"]["state"] == "error"
    assert "interrupted" in snap["current"]["error"]
    assert snap["last"]["backup"]["state"] == "error"


def test_results_per_kind_survive_other_jobs(vbox_dir):
    jobs.start("recon", lambda: {"r": 1}, actor="a")
    wait_idle()
    jobs.start("backup", lambda: {"b": 1}, actor="a")
    wait_idle()
    last = jobs.snapshot()["last"]
    assert last["recon"]["result"] == {"r": 1}
    assert last["backup"]["result"] == {"b": 1}


def test_unknown_kind_rejected(vbox_dir):
    with pytest.raises(ValueError):
        jobs.start("rm -rf", lambda: {}, actor="a")


def test_empty_state_when_nothing_ran(vbox_dir):
    assert jobs.snapshot() == {"current": None, "last": {}}


@pytest.mark.skipif(os.geteuid() != 0, reason="chown to another uid needs root")
def test_job_files_belong_to_the_data_dir_owner(tmp_path, monkeypatch):
    data = tmp_path / "vulnbox-data"
    data.mkdir()
    os.chown(data, 4242, 4242)
    monkeypatch.setenv("W4RYA_VULNBOX_DIR", str(data))
    jobs.start("recon", lambda: {}, actor="a")
    wait_idle()
    for p in (vconfig.job_path(), vconfig.job_lock_path()):
        assert p.stat().st_uid == 4242, p
