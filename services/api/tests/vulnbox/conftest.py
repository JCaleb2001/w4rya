"""Shared fixtures for the vulnbox package tests.

Inherits the top-level conftest (import path + dead TIMESCALE/secret so the
route suite runs offline). Here we only add the one thing specific to this
package: a tmp data directory, so nothing ever writes to the real
`/app/vulnbox-data`.
"""

import pytest

from vulnbox import config as vconfig


@pytest.fixture
def vbox_dir(tmp_path, monkeypatch):
    """Point the vulnbox data dir at a tmp path and create its tree."""
    d = tmp_path / "vulnbox-data"
    monkeypatch.setenv("W4RYA_VULNBOX_DIR", str(d))
    vconfig.init_paths()
    return d
