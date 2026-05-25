"""Make services/api/ importable from the tests/ subdir without setup.py."""

import os
import sys

# add the parent dir (services/api) to sys.path so `import rate_limit` etc works
_HERE = os.path.dirname(os.path.abspath(__file__))
_API = os.path.abspath(os.path.join(_HERE, ".."))
if _API not in sys.path:
    sys.path.insert(0, _API)
