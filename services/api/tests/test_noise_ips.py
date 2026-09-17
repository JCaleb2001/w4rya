"""noise_ips: the config key behind the "hide checker + our own traffic" filter.

The parsing is pure, so most of this needs no app at all. The one route test
covers the wiring that actually matters: `hide_noise` in the request body has
to reach FlowQuery.ip_src_exclude, because the frontend deliberately doesn't
know which ips count as noise -- it only sends the intent.
"""

from ipaddress import ip_network

import pytest

import app_config


# --- parsing ---------------------------------------------------------------

def test_empty_values_parse_to_nothing():
    for raw in ("", None, "   ", ",, ,"):
        assert app_config.parse_noise_ips(raw) == []


def test_plain_ips_and_cidrs_both_parse():
    nets = app_config.parse_noise_ips("10.100.0.1, 10.60.0.0/16")
    assert nets == [ip_network("10.100.0.1/32"), ip_network("10.60.0.0/16")]


def test_semicolons_are_accepted_as_separators():
    """Muscle memory from other tools; cheaper to accept than to explain."""
    assert len(app_config.parse_noise_ips("10.0.0.1; 10.0.0.2")) == 2


def test_host_bits_are_tolerated():
    """strict=False, so a pasted 10.60.5.1/16 is read as its network rather
    than rejected on a detail the operator doesn't care about."""
    assert app_config.parse_noise_ips("10.60.5.1/16") == [ip_network("10.60.0.0/16")]


# --- write-time validation -------------------------------------------------

def test_coerce_normalises_spacing():
    assert app_config.coerce_scalar("noise_ips", "10.0.0.1,10.0.0.2") == \
        "10.0.0.1/32, 10.0.0.2/32"


def test_coerce_rejects_a_typo():
    """A bad entry has to fail loudly at write time. Silently dropping it would
    just make the checker reappear in the flow list with no explanation."""
    with pytest.raises(ValueError):
        app_config.coerce_scalar("noise_ips", "10.100.0.1, not-an-ip")


def test_noise_ips_is_an_editable_scalar():
    assert "noise_ips" in app_config.SCALAR_KEYS


# --- route wiring ----------------------------------------------------------

def test_hide_noise_reaches_the_query(viewer, monkeypatch, webservice_mod):
    captured = {}

    class _Conn:
        def flow_query(self, q):
            captured["ip_src_exclude"] = q.ip_src_exclude
            return []

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(webservice_mod, "db", type("D", (), {"connection": lambda s: _Conn()})())
    monkeypatch.setattr(app_config, "get", lambda key, default=None:
                        "10.100.0.1" if key == "noise_ips" else ([] if key == "services" else default))

    viewer.post("/query", json={"hide_noise": True})
    assert captured["ip_src_exclude"] == [ip_network("10.100.0.1/32")]

    viewer.post("/query", json={})
    assert captured["ip_src_exclude"] == []


def test_hide_noise_also_folds_in_confirmed_checker_ips(viewer, monkeypatch, webservice_mod):
    """An operator confirming a checker IP via the Checker tab's suggestion
    flow (checker_ips, distinct config key from noise_ips) shouldn't also
    have to retype it into the noise_ips field to get it hidden from the
    flow list -- both lists mean the same thing ("not an attacker") and
    hide_noise should honor both."""
    captured = {}

    class _Conn:
        def flow_query(self, q):
            captured["ip_src_exclude"] = q.ip_src_exclude
            return []

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(webservice_mod, "db", type("D", (), {"connection": lambda s: _Conn()})())
    monkeypatch.setattr(app_config, "get", lambda key, default=None: {
        "noise_ips": "10.100.0.1",
        "checker_ips": ["10.200.0.9"],
        "services": [],
    }.get(key, default))

    viewer.post("/query", json={"hide_noise": True})
    assert captured["ip_src_exclude"] == [
        ip_network("10.100.0.1/32"),
        ip_network("10.200.0.9/32"),
    ]
