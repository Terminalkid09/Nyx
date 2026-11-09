"""Pick a listening port without crashing when the preferred one is taken.

Nyx binds three things: the API (default 8000), the proxy (8080) and the CA
portal (18081). Any of them can already be held by an unrelated process — a dev
server, another security tool, an old Nyx instance still shutting down — and a
hard crash on startup is the worst possible answer for a desktop app.

The desktop shell picks free ports before spawning the backend and tells it
through ``API_PORT``/``PROXY_PORT``. This module is the safety net for direct
runs (``python main.py``, the packaged binary started by hand, tests) and for
the race where a port is grabbed between the check and the bind.
"""
from __future__ import annotations

import logging
import os
import socket

logger = logging.getLogger(__name__)

# Bounded so a machine with an exhausted range fails fast instead of hanging.
DEFAULT_ATTEMPTS = 25


def is_port_free(port: int, host: str = "127.0.0.1") -> bool:
    """True when a TCP listener can bind ``host:port`` right now."""
    if not 1 <= int(port) <= 65535:
        return False
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        # No SO_REUSEADDR: we want to know whether *someone else* holds it.
        # On Windows that is not enough: a plain bind can steal a port that a
        # listener bound to another address held with SO_REUSEADDR (127.0.0.1
        # vs 0.0.0.0), which is why a busy proxy port used to look free.
        if os.name == "nt" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        sock.bind((host or "127.0.0.1", int(port)))
        return True
    except OSError:
        return False
    finally:
        try:
            sock.close()
        except OSError:
            pass


def pick_free_port(
    preferred: int,
    host: str = "127.0.0.1",
    attempts: int = DEFAULT_ATTEMPTS,
) -> int:
    """Return ``preferred`` when free, otherwise the next free port.

    Falls back to ``preferred`` when the whole window is taken: the caller then
    fails with a clear message instead of silently listening somewhere nobody
    expects.
    """
    start = max(1, int(preferred))
    for candidate in range(start, min(65535, start + max(1, attempts)) + 1):
        if is_port_free(candidate, host):
            if candidate != start:
                logger.warning(
                    "Port %d is taken; using %d instead", start, candidate
                )
            return candidate
    logger.error(
        "No free port in %d-%d (checked %d candidates)", start, start + attempts, attempts
    )
    return start
