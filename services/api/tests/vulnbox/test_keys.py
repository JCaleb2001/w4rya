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


def test_fingerprint_matches_ssh_keygen(vbox_dir):
    """The in-process fingerprint must equal what ssh-keygen -lf prints —
    it's what operators compare against the platform."""
    import subprocess
    s = keys.generate()
    out = subprocess.run(["ssh-keygen", "-lf", str(keys.private_key_path()) + ".pub"],
                         capture_output=True, text=True, check=True).stdout
    assert s["fingerprint"] in out.split()


def test_fingerprint_of_garbage_is_none():
    assert keys.fingerprint("") is None
    assert keys.fingerprint("ssh-ed25519 not-base64!!") is None


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
    kh.write_text("192.0.2.10 ssh-ed25519 AAAA...\n")
    assert keys.forget_host_key() is True
    assert not kh.exists()


@pytest.mark.skipif(os.geteuid() != 0, reason="chown to another uid needs root")
def test_key_files_belong_to_the_data_dir_owner(tmp_path, monkeypatch):
    """The host user must be able to read the key (scripts/backup.sh copies it)."""
    from vulnbox import config as vconfig
    data = tmp_path / "vulnbox-data"
    data.mkdir()
    os.chown(data, 4242, 4242)
    monkeypatch.setenv("W4RYA_VULNBOX_DIR", str(data))
    keys.generate()
    for p in (vconfig.keys_dir(), vconfig.private_key_path(), vconfig.public_key_path()):
        assert p.stat().st_uid == 4242, p
