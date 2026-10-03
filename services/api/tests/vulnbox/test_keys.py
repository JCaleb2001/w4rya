"""SSH keypair lifecycle. Uses the real ssh-keygen (present in the api image's
python:3.10 base via buildpack-deps' openssh-client), so these also prove the
binary is driven correctly."""

import os
import stat

import pytest

from vulnbox import keys


def test_status_empty_when_no_key(vbox_dir):
    s = keys.status()
    assert s["exists"] is False
    assert "public_key" not in s or s.get("public_key") in (None, "")


def test_generate_creates_0600_private_and_public(vbox_dir):
    s = keys.generate()
    assert s["exists"] is True
    assert s["public_key"].startswith("ssh-ed25519 ")
    assert s["fingerprint"].startswith("SHA256:")
    # private key present and locked down
    priv = keys.private_key_path()
    assert priv.exists()
    mode = stat.S_IMODE(os.stat(priv).st_mode)
    assert mode == 0o600, oct(mode)


def test_status_never_leaks_private_material(vbox_dir):
    keys.generate()
    s = keys.status()
    blob = repr(s)
    assert "PRIVATE KEY" not in blob
    assert "ssh-ed25519" in s["public_key"]
    # no key value in the dict should contain the private file's bytes
    priv_bytes = keys.private_key_path().read_text()
    assert priv_bytes not in blob


def test_generate_refuses_overwrite_without_rotate(vbox_dir):
    keys.generate()
    with pytest.raises(ValueError):
        keys.generate()


def test_generate_rotate_replaces_key(vbox_dir):
    first = keys.generate()
    second = keys.generate(rotate=True)
    assert second["exists"] is True
    assert second["fingerprint"] != first["fingerprint"]


def test_forget_host_key(vbox_dir):
    from vulnbox import config as vconfig
    assert keys.forget_host_key() is False  # nothing pinned yet
    kh = vconfig.known_hosts_path()
    kh.write_text("10.60.3.2 ssh-ed25519 AAAA...\n")
    assert keys.forget_host_key() is True
    assert not kh.exists()
