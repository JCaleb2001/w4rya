"""Edge cases on the three endpoints that touch something outside the api:
the filesystem (/download/), a third-party URL (/under_attack) and the database
(/healthz).

Two of the three are the ones an attacker reaches for first — an arbitrary-file
read and an SSRF — so the guards get pinned here rather than left to manual
testing.
"""

import types

import pytest
import requests

import app_config


@pytest.fixture
def traffic_dir(tmp_path, monkeypatch, webservice_mod):
    """Point the download root at a temp dir.

    `webservice.py` does `from configurations import traffic_dir`, which binds
    the Path by value at import time — patching `configurations.traffic_dir`
    would have no effect on the handler.
    """
    root = tmp_path / "traffic"
    root.mkdir()
    monkeypatch.setattr(webservice_mod, "traffic_dir", root)
    monkeypatch.setattr(webservice_mod, "dump_pcaps_dir", root)
    return root


@pytest.fixture
def visualizer(monkeypatch):
    """Set the visualizer_url config value without a database."""
    def _set(url):
        monkeypatch.setattr(
            app_config, "get",
            lambda key, default=None: url if key == "visualizer_url" else default,
        )
    return _set


def fake_requests(get):
    """A stand-in for the `requests` module. `exceptions` has to be the real
    one — the handler catches requests.exceptions.RequestException."""
    return types.SimpleNamespace(get=get, exceptions=requests.exceptions)


# --- /download/ ------------------------------------------------------------

def test_download_requires_a_file_argument(viewer, traffic_dir):
    resp = viewer.get("/download/")
    assert resp.status_code == 400
    assert "no 'file' given" in resp.get_data(as_text=True)


def test_download_refuses_a_traversal_out_of_the_traffic_dir(viewer, traffic_dir):
    """The classic one: /download/?file=../../../etc/passwd on an api that is
    reachable by every teammate."""
    resp = viewer.get("/download/", query_string={"file": "../../../etc/passwd"})
    assert resp.status_code == 403
    assert "outside allowed roots" in resp.get_data(as_text=True)


@pytest.mark.parametrize("path", [
    "/etc/passwd",
    "/app/webservice.py",
    "/proc/self/environ",
])
def test_download_refuses_an_absolute_path_outside_the_allowed_roots(viewer, traffic_dir, path):
    """An absolute path skips the traffic_dir join entirely, so it needs its
    own check — /app/webservice.py and /proc/self/environ would both leak the
    session signing key."""
    resp = viewer.get("/download/", query_string={"file": path})
    assert resp.status_code == 403
    assert "outside allowed roots" in resp.get_data(as_text=True)


def test_download_serves_a_file_inside_the_traffic_dir(viewer, traffic_dir):
    (traffic_dir / "capture.pcap").write_bytes(b"\xd4\xc3\xb2\xa1pcap-bytes")
    resp = viewer.get("/download/", query_string={"file": "capture.pcap"})
    assert resp.status_code == 200
    assert resp.data == b"\xd4\xc3\xb2\xa1pcap-bytes"
    assert "attachment" in resp.headers["Content-Disposition"]


def test_download_serves_a_file_in_a_subdirectory(viewer, traffic_dir):
    sub = traffic_dir / "2024-11-30"
    sub.mkdir()
    (sub / "capture.pcap").write_bytes(b"nested")
    resp = viewer.get("/download/", query_string={"file": "2024-11-30/capture.pcap"})
    assert resp.status_code == 200
    assert resp.data == b"nested"


def test_download_accepts_an_absolute_path_that_stays_inside_the_root(viewer, traffic_dir):
    (traffic_dir / "capture.pcap").write_bytes(b"abs")
    resp = viewer.get("/download/", query_string={"file": str(traffic_dir / "capture.pcap")})
    assert resp.status_code == 200
    assert resp.data == b"abs"


def test_download_of_a_missing_file_is_a_404(viewer, traffic_dir):
    resp = viewer.get("/download/", query_string={"file": "nope.pcap"})
    assert resp.status_code == 404
    assert "file not found" in resp.get_data(as_text=True)


def test_download_refuses_a_symlink_that_escapes_the_root(viewer, traffic_dir):
    link = traffic_dir / "shortcut"
    link.symlink_to("/etc/passwd")
    resp = viewer.get("/download/", query_string={"file": "shortcut"})
    assert resp.status_code == 403
    assert "outside allowed roots" in resp.get_data(as_text=True)


def test_a_symlink_pointing_inside_the_root_is_followed(viewer, traffic_dir):
    # FINDING: the `if target.is_symlink(): return 403 'symlinks not allowed'`
    # branch in downloadFile is unreachable. `Path.resolve()` on the line above
    # has already dereferenced the link, so `target` is the real path and
    # `is_symlink()` is always False. Escaping symlinks are still caught (by
    # the allowed-roots check, as the test above shows), so this is dead code
    # rather than a hole — but the file it claims to reject is served.
    (traffic_dir / "real.pcap").write_bytes(b"linked")
    (traffic_dir / "alias.pcap").symlink_to(traffic_dir / "real.pcap")
    resp = viewer.get("/download/", query_string={"file": "alias.pcap"})
    assert resp.status_code == 200
    assert resp.data == b"linked"


def test_download_is_not_reachable_anonymously(anon):
    assert anon.get("/download/", query_string={"file": "x"}).status_code == 401


# --- /under_attack ---------------------------------------------------------

def test_under_attack_is_a_no_op_when_no_visualizer_is_configured(viewer, visualizer):
    """visualizer_url is empty by default; the frontend polls this endpoint
    regardless, so it has to answer 200 with nothing rather than error."""
    visualizer("")
    resp = viewer.get("/under_attack")
    assert resp.status_code == 200
    assert resp.get_json() == {}


@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "javascript:alert(1)",
    "gopher://127.0.0.1:11211/_stats",
    "ftp://127.0.0.1/",
    "//evil.example.com",
    "http://",
])
def test_under_attack_refuses_a_non_http_visualizer_url(viewer, visualizer, url):
    """SSRF guard. visualizer_url is admin-editable at runtime, so a typo'd or
    hostile value must not become a request the api makes on the caller's
    behalf."""
    visualizer(url)
    resp = viewer.get("/under_attack")
    assert resp.status_code == 400
    assert resp.get_json() == {"error": "visualizer_url invalid"}


def test_under_attack_is_a_502_when_the_visualizer_is_unreachable(
    viewer, visualizer, monkeypatch, webservice_mod
):
    """A wedged or absent visualizer is an upstream failure, not a bug in this
    api — 502 keeps it distinguishable in the UI."""
    def boom(*a, **kw):
        raise requests.exceptions.ConnectionError("connection refused")

    visualizer("http://visualizer.invalid:8080")
    monkeypatch.setattr(webservice_mod, "requests", fake_requests(boom))
    resp = viewer.get("/under_attack")
    assert resp.status_code == 502
    assert "connection refused" in resp.get_json()["error"]


def test_under_attack_is_a_502_when_the_visualizer_times_out(
    viewer, visualizer, monkeypatch, webservice_mod
):
    def boom(*a, **kw):
        raise requests.exceptions.Timeout("timed out")

    visualizer("https://visualizer.invalid")
    monkeypatch.setattr(webservice_mod, "requests", fake_requests(boom))
    assert viewer.get("/under_attack").status_code == 502


def test_under_attack_passes_a_hard_timeout_and_forbids_redirects(
    viewer, visualizer, monkeypatch, webservice_mod
):
    """allow_redirects=False is part of the SSRF guard: without it a validated
    http:// visualizer could bounce the api to file:// or a metadata service."""
    seen = {}

    def capture(url, **kw):
        seen["url"] = url
        seen.update(kw)
        return types.SimpleNamespace(status_code=200, json=lambda: {"1": True})

    visualizer("http://visualizer.invalid:8080")
    monkeypatch.setattr(webservice_mod, "requests", fake_requests(capture))
    resp = viewer.get("/under_attack", query_string={"from_tick": "3", "to_tick": "5"})
    assert resp.status_code == 200
    assert resp.get_json() == {"1": True}
    assert seen["url"] == "http://visualizer.invalid:8080/api/under-attack"
    assert seen["params"] == {"from_tick": "3", "to_tick": "5"}
    assert seen["timeout"] == 3
    assert seen["allow_redirects"] is False


def test_under_attack_is_a_502_on_an_upstream_error_status(
    viewer, visualizer, monkeypatch, webservice_mod
):
    visualizer("http://visualizer.invalid:8080")
    monkeypatch.setattr(webservice_mod, "requests", fake_requests(
        lambda *a, **kw: types.SimpleNamespace(status_code=500, json=lambda: {})
    ))
    resp = viewer.get("/under_attack")
    assert resp.status_code == 502
    assert resp.get_json()["error"] == "visualizer http 500"


def test_under_attack_is_a_502_when_the_visualizer_returns_non_json(
    viewer, visualizer, monkeypatch, webservice_mod
):
    def html(*a, **kw):
        def _json():
            raise ValueError("not json")
        return types.SimpleNamespace(status_code=200, json=_json)

    visualizer("http://visualizer.invalid:8080")
    monkeypatch.setattr(webservice_mod, "requests", fake_requests(html))
    resp = viewer.get("/under_attack")
    assert resp.status_code == 502
    assert resp.get_json()["error"] == "visualizer returned non-JSON"


# --- /healthz --------------------------------------------------------------

def test_healthz_is_200_when_the_database_answers(anon, fake_db):
    """Docker's healthcheck calls this unauthenticated; a 401 here would mark
    a perfectly healthy container as unhealthy forever."""
    resp = anon.get("/healthz")
    assert resp.status_code == 200
    assert resp.get_json() == {"ok": True, "db": "up"}


def test_healthz_is_503_when_the_database_is_down(anon, monkeypatch, webservice_mod):
    class DeadPool:
        def connection(self):
            raise RuntimeError("could not connect to server")

    monkeypatch.setattr(webservice_mod, "db", DeadPool())
    resp = anon.get("/healthz")
    assert resp.status_code == 503
    body = resp.get_json()
    assert body["ok"] is False
    assert "could not connect" in body["error"]


def test_healthz_is_reachable_without_a_session(anon, fake_db):
    """It is in PUBLIC_PATHS on purpose: container healthchecks carry no
    cookie."""
    assert anon.get("/healthz").status_code == 200
