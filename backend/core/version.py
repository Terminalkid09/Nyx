"""Single source of truth for the Nyx release version.

The API (/health), the CLI (--version) and the desktop build all read the
version from here. Keeping one constant stops the three surfaces from drifting
apart (desktop 1.0.0 vs frontend 0.1.0 vs CLI 1.1.0 was the v1.0.0 state).
"""

VERSION = "2.0.0"

__version__ = VERSION
