"""Pure config/validator paths for the vulnbox module."""

import pytest

import app_config
from vulnbox import config as vconfig


# --- resolve_host ----------------------------------------------------------

def test_resolve_host_derives_from_team_id():
    assert vconfig.resolve_host("3", "") == "10.60.3.2"
    assert vconfig.resolve_host("1", "") == "10.60.1.2"


def test_resolve_host_override_wins():
    assert vconfig.resolve_host("3", "10.9.9.9") == "10.9.9.9"
    assert vconfig.resolve_host("3", "vulnbox.demo") == "vulnbox.demo"


def test_resolve_host_raises_without_usable_input():
    with pytest.raises(ValueError):
        vconfig.resolve_host("", "")
    with pytest.raises(ValueError):
        vconfig.resolve_host("notanumber", "")


def test_resolve_host_rejects_out_of_range_team_id():
    with pytest.raises(ValueError):
        vconfig.resolve_host("300", "")


def test_resolve_host_rejects_bogus_override():
    with pytest.raises(ValueError):
        vconfig.resolve_host("3", "10.0.0.1; rm -rf /")


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


def test_validate_host_override_allows_empty():
    assert vconfig.validate_host_override("") == ""
    assert vconfig.validate_host_override("10.60.3.2") == "10.60.3.2"
    with pytest.raises(ValueError):
        vconfig.validate_host_override("bad ip")


# --- app_config integration ------------------------------------------------

def test_vulnbox_keys_are_registered_scalars():
    for key in ("vulnbox_ip", "vulnbox_user", "vulnbox_ssh_port", "vulnbox_services_path"):
        assert key in app_config.SCALAR_KEYS
        assert key in app_config.DEFAULTS


def test_coerce_scalar_handles_vulnbox_keys():
    assert app_config.coerce_scalar("vulnbox_ssh_port", "2222") == 2222
    assert app_config.coerce_scalar("vulnbox_user", "root") == "root"
    assert app_config.coerce_scalar("vulnbox_services_path", "/srv") == "/srv"
    assert app_config.coerce_scalar("vulnbox_ip", "") == ""
    with pytest.raises(ValueError):
        app_config.coerce_scalar("vulnbox_ssh_port", "99999")
    with pytest.raises(ValueError):
        app_config.coerce_scalar("vulnbox_services_path", "relative/path")


# --- paths are env-driven --------------------------------------------------

def test_paths_follow_env(vbox_dir):
    assert str(vconfig.data_dir()) == str(vbox_dir)
    assert vconfig.keys_dir().is_dir()
    assert vconfig.backups_dir().is_dir()
    assert vconfig.private_key_path().parent == vconfig.keys_dir()
