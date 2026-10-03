"""Vulnbox ops module — prepare and defend our own A/D vulnbox.

Public surface: the Flask Blueprint `bp` (registered once in webservice.py)
and `init_paths()` (called from create_app). See README.md for what it does,
the data flow, and the security decisions.

No AI / LLM at runtime: everything here is deterministic SSH / git / ssh-keygen.
"""

from .config import init_paths
from .routes import bp

__all__ = ["bp", "init_paths"]
