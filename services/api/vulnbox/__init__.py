"""Vulnbox ops module — prepare and defend our own A/D vulnbox.

Public surface is the Flask Blueprint `bp`, registered once in webservice.py.
See README.md for what it does, the data flow, and the security decisions.

No AI / LLM at runtime: everything here is deterministic SSH / git / ssh-keygen.
"""

from __future__ import annotations

__all__ = ["bp", "set_pool", "init_paths"]


def __getattr__(name):
    # Lazy attribute access so `import vulnbox` (done at webservice import time)
    # pulls in routes.py only when `bp` is actually read, after app_config and
    # the other base modules have finished importing. Keeps import order free
    # of cycles and does no filesystem work at import.
    if name == "bp":
        from .routes import bp
        return bp
    if name == "set_pool":
        from .routes import set_pool
        return set_pool
    if name == "init_paths":
        from .config import init_paths
        return init_paths
    raise AttributeError(f"module 'vulnbox' has no attribute {name!r}")
