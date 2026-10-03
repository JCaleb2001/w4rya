"""`GET /pipeline/health`, offline.

The route mixes two sources — a database read and a directory listing — so the
fixtures here fake both: a connection object whose two query methods return
canned values, and a tmp_path standing in for the capture directory.

The status field is the part worth pinning down. It is what the war-room panel
colours on, and the difference between "lagging" and "stalled" is the
difference between chasing the vulnbox and chasing the assembler.
"""

from datetime import datetime, timedelta, timezone

import pytest

import configurations


class _Conn:
    def __init__(self, last_flow_time, ingested):
        self._last = last_flow_time
        self._ingested = ingested

    def pipeline_health(self, tick_start, hour_start, horizon):
        return {
            "last_flow_time": self._last,
            "flows_last_tick": 7,
            "flows_last_hour": 42,
        }

    def ingested_pcap_names(self):
        return list(self._ingested)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _Db:
    def __init__(self, conn):
        self._conn = conn

    def connection(self):
        return self._conn


@pytest.fixture
def pipeline(monkeypatch, webservice_mod, tmp_path):
    """Drive the route: pick the age of the newest flow and what is on disk."""

    def _setup(*, flow_age_seconds=None, on_disk=(), ingested=(), dir_exists=True):
        last = None
        if flow_age_seconds is not None:
            last = datetime.now(tz=timezone.utc) - timedelta(seconds=flow_age_seconds)

        capture_dir = tmp_path / "traffic"
        if dir_exists:
            capture_dir.mkdir(exist_ok=True)
            for name in on_disk:
                (capture_dir / name).write_bytes(b"")
        monkeypatch.setattr(configurations, "traffic_dir", capture_dir)
        monkeypatch.setattr(webservice_mod, "db", _Db(_Conn(last, ingested)))

    return _setup


def test_requires_a_session(anon, pipeline):
    pipeline(flow_age_seconds=5)
    assert anon.get("/pipeline/health").status_code == 401


def test_fresh_traffic_is_ok(viewer, pipeline):
    pipeline(flow_age_seconds=5, on_disk=["a.pcap"], ingested=["a.pcap"])
    body = viewer.get("/pipeline/health").get_json()
    assert body["status"] == "ok"
    assert body["flows"] == {"last_tick": 7, "last_hour": 42}
    assert body["lag_seconds"] == pytest.approx(5, abs=2)


def test_no_recent_flows_reads_as_idle(viewer, pipeline):
    """A fresh install, or one whose assembler has never ingested anything."""
    pipeline(flow_age_seconds=None)
    body = viewer.get("/pipeline/health").get_json()
    assert body["status"] == "idle"
    assert body["lag_seconds"] is None


def test_old_flows_with_nothing_waiting_is_lagging(viewer, pipeline):
    """Everything on disk is ingested, so the gap is upstream of the
    assembler: the capture or the pull loop."""
    pipeline(flow_age_seconds=3600, on_disk=["a.pcap"], ingested=["a.pcap"])
    body = viewer.get("/pipeline/health").get_json()
    assert body["status"] == "lagging"
    assert body["pcaps"]["pending"] == 0
    assert "vulnbox" in body["detail"]


def test_old_flows_with_pcaps_waiting_is_stalled(viewer, pipeline):
    """Files landed but never made it into the flow table — that is the
    assembler, and the detail line says so."""
    pipeline(flow_age_seconds=3600, on_disk=["a.pcap", "b.pcap"], ingested=["a.pcap"])
    body = viewer.get("/pipeline/health").get_json()
    assert body["status"] == "stalled"
    assert body["pcaps"]["pending"] == 1
    assert "assembler" in body["detail"]


def test_counts_and_names_come_from_disk(viewer, pipeline):
    pipeline(flow_age_seconds=5, on_disk=["a.pcap", "b.pcapng"], ingested=["a.pcap"])
    pcaps = viewer.get("/pipeline/health").get_json()["pcaps"]
    assert pcaps["readable"] is True
    assert pcaps["on_disk"] == 2
    assert pcaps["ingested"] == 1
    assert pcaps["newest_on_disk"] == "b.pcapng"


def test_non_pcap_files_are_ignored(viewer, pipeline):
    """tcpdump.log and friends share the directory."""
    pipeline(flow_age_seconds=5, on_disk=["a.pcap", "tcpdump.log", ".tcpdump.pid"])
    assert viewer.get("/pipeline/health").get_json()["pcaps"]["on_disk"] == 1


def test_missing_capture_dir_degrades_instead_of_500(viewer, pipeline):
    """An api container started before the traffic mount existed still has to
    answer — the database half of the check is the useful half."""
    pipeline(flow_age_seconds=5, dir_exists=False)
    resp = viewer.get("/pipeline/health")
    assert resp.status_code == 200
    pcaps = resp.get_json()["pcaps"]
    assert pcaps["readable"] is False
    assert pcaps["on_disk"] is None
    assert pcaps["pending"] is None


def test_stale_threshold_follows_the_tick_length(viewer, pipeline, monkeypatch):
    """The window is two ticks, so a long tick tolerates a longer gap."""
    import app_config
    monkeypatch.setattr(app_config, "get", lambda key: 600000 if key == "tick_length" else None)
    pipeline(flow_age_seconds=900, on_disk=["a.pcap"], ingested=["a.pcap"])
    body = viewer.get("/pipeline/health").get_json()
    assert body["stale_after_seconds"] == 1200
    assert body["status"] == "ok"
