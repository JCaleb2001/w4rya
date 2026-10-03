"""Pure config/validator paths for the vulnbox module."""

import os

import pytest

import app_config
from vulnbox import config as vconfig


# --- resolve_host (from /config's vm_ip) -----------------------------------

@pytest.mark.parametrize("raw", ["192.0.2.10", "2001:db8::2", "vulnbox.example", " 192.0.2.10 "])
def test_resolve_host_accepts_ips_and_hostnames(raw):
    assert vconfig.resolve_host(raw) == raw.strip()


@pytest.mark.parametrize("raw", ["", None, "   "])
def test_resolve_host_unset_says_how_to_fix_it(raw):
    with pytest.raises(ValueError, match="vm_ip"):
        vconfig.resolve_host(raw)


@pytest.mark.parametrize("raw", ["192.0.2.10; rm -rf /", "a b", "host$(id)"])
def test_resolve_host_rejects_junk(raw):
    with pytest.raises(ValueError):
        vconfig.resolve_host(raw)


@pytest.mark.skipif("VM_IP" in os.environ, reason="this environment sets VM_IP")
def test_vm_ip_has_no_placeholder_default():
    """Unset means unset: /vulnbox then says what to configure instead of
    connecting to a made-up address that may be another team's box."""
    assert app_config.DEFAULTS["vm_ip"] == ""
    with pytest.raises(ValueError, match="vm_ip"):
        vconfig.resolve_host(app_config.DEFAULTS["vm_ip"])


def test_is_ipv6():
    assert vconfig.is_ipv6("2001:db8::2")
    assert not vconfig.is_ipv6("192.0.2.10")
    assert not vconfig.is_ipv6("vulnbox.example")


# --- service port ranges ----------------------------------------------------

def test_parse_port_ranges():
    assert vconfig.parse_port_ranges("9000-9999, 31337") == ((9000, 9999), (31337, 31337))
    assert vconfig.parse_port_ranges("") == ()
    assert vconfig.parse_port_ranges(None) == ()


@pytest.mark.parametrize("raw", ["abc", "10-", "0", "70000", "9999-9000", "1-2-3"])
def test_parse_port_ranges_rejects_bad_input(raw):
    with pytest.raises(ValueError):
        vconfig.parse_port_ranges(raw)


def test_in_port_ranges_with_no_ranges_matches_everything():
    assert vconfig.in_port_ranges(22, ())
    ranges = vconfig.parse_port_ranges("9000-9999")
    assert vconfig.in_port_ranges(9000, ranges)
    assert not vconfig.in_port_ranges(8080, ranges)


def test_validate_service_ports_normalizes():
    assert vconfig.validate_service_ports(" 9000-9999 ,31337,31337-31337") == "9000-9999,31337,31337"
    assert vconfig.validate_service_ports("") == ""


# --- service name guard ----------------------------------------------------

@pytest.mark.parametrize("name", ["svc", "web-1", "a_b.c", "Service9000"])
def test_valid_service_names(name):
    assert vconfig.is_valid_service_name(name)


@pytest.mark.parametrize("name", ["", ".", "..", "../etc", "a b", "a;b", "a/b", "a$b", "a|b"])
def test_hostile_service_names_rejected(name):
    assert not vconfig.is_valid_service_name(name)


# --- scalar validators -----------------------------------------------------

def test_validate_port_ok_and_range():
    assert vconfig.validate_port("22") == 22
    with pytest.raises(ValueError):
        vconfig.validate_port("0")
    with pytest.raises(ValueError):
        vconfig.validate_port("70000")
    with pytest.raises(ValueError):
        vconfig.validate_port("nope")


def test_validate_username():
    assert vconfig.validate_username("root") == "root"
    with pytest.raises(ValueError):
        vconfig.validate_username("ro ot")


def test_validate_services_path_must_be_absolute():
    assert vconfig.validate_services_path("/root/services") == "/root/services"
    with pytest.raises(ValueError):
        vconfig.validate_services_path("root/services")


# --- app_config integration ------------------------------------------------

VULNBOX_KEYS = ("vulnbox_user", "vulnbox_ssh_port", "vulnbox_services_path", "vulnbox_service_ports")


def test_vulnbox_keys_are_registered_scalars():
    for key in VULNBOX_KEYS:
        assert key in app_config.SCALAR_KEYS
        assert key in app_config.DEFAULTS


def test_coerce_scalar_handles_vulnbox_keys():
    assert app_config.coerce_scalar("vulnbox_ssh_port", "2222") == 2222
    assert app_config.coerce_scalar("vulnbox_user", "root") == "root"
    assert app_config.coerce_scalar("vulnbox_services_path", "/srv") == "/srv"
    assert app_config.coerce_scalar("vulnbox_service_ports", "9000-9999") == "9000-9999"
    with pytest.raises(ValueError):
        app_config.coerce_scalar("vulnbox_ssh_port", "99999")
    with pytest.raises(ValueError):
        app_config.coerce_scalar("vulnbox_services_path", "relative/path")
    with pytest.raises(ValueError):
        app_config.coerce_scalar("vulnbox_service_ports", "not-a-port")


# --- paths are env-driven --------------------------------------------------

def test_paths_follow_env(vbox_dir):
    assert str(vconfig.data_dir()) == str(vbox_dir)
    assert vconfig.keys_dir().is_dir()
    assert vconfig.backups_dir().is_dir()
    assert vconfig.private_key_path().parent == vconfig.keys_dir()


# --- ownership: everything under the data dir belongs to its owner ----------

needs_root = pytest.mark.skipif(os.geteuid() != 0, reason="chown to another uid needs root")
OTHER_UID = 4242  # stands in for the host user who owns the bind mount


@needs_root
def test_ensure_dir_gives_created_dirs_to_the_data_dir_owner(tmp_path, monkeypatch):
    data = tmp_path / "vulnbox-data"
    data.mkdir()
    os.chown(data, OTHER_UID, OTHER_UID)
    monkeypatch.setenv("W4RYA_VULNBOX_DIR", str(data))
    vconfig.init_paths()
    for d in (vconfig.keys_dir(), vconfig.backups_dir()):
        assert d.stat().st_uid == OTHER_UID, d


@needs_root
def test_init_paths_repairs_root_owned_subdirs(tmp_path, monkeypatch):
    data = tmp_path / "vulnbox-data"
    (data / "keys").mkdir(parents=True)  # left root-owned by an older run
    os.chown(data, OTHER_UID, OTHER_UID)
    monkeypatch.setenv("W4RYA_VULNBOX_DIR", str(data))
    vconfig.init_paths()
    assert vconfig.keys_dir().stat().st_uid == OTHER_UID


@pytest.mark.parametrize("raw", ["-Elog", "-oProxyCommand", ".hidden"])
def test_usernames_cannot_start_like_an_option(raw):
    with pytest.raises(ValueError):
        vconfig.validate_username(raw)


@pytest.mark.parametrize("raw", ["-oProxyCommand", ".host", "-x.example"])
def test_hostnames_cannot_start_like_an_option(raw):
    with pytest.raises(ValueError):
        vconfig.resolve_host(raw)


def test_is_ip():
    assert vconfig.is_ip("192.0.2.10") and vconfig.is_ip("2001:db8::2")
    assert not vconfig.is_ip("vulnbox.example")
