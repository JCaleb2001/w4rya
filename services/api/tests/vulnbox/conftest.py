"""Shared fixtures for the vulnbox package tests.

Inherits the top-level conftest: import path, dead TIMESCALE/secret so the
route suite runs offline, and `_isolate_vulnbox_dir`, which already points
W4RYA_VULNBOX_DIR at a per-test tmp path. Here we only create its tree.
"""

import pytest

from vulnbox import config as vconfig


@pytest.fixture
def vbox_dir():
    """The per-test vulnbox data dir, with keys/ and backups/ created."""
    vconfig.init_paths()
    return vconfig.data_dir()
