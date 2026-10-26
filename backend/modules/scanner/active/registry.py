"""Single registry for the active checks.

Adding a check used to mean two edits in two files (an import plus an instance
appended to a 140-line list), and forgetting the second one silently shipped a
check that never ran. Discovery is by class now: a module in this package that
defines a ``BaseCheck`` subclass is picked up on the next start.

Order is module path then class name — deterministic across runs, which the
scanner relies on because results are processed in registration order, so
dedupe and persisted findings stay stable between scans.

Two safety rails:
  - a class that cannot be constructed is logged and skipped, instead of taking
    every scan down with it;
  - two classes declaring the same ``name`` are collapsed to the first one,
    because two checks with one identity are reported as one issue anyway.
"""
from __future__ import annotations

import importlib
import logging
import pkgutil

from modules.scanner.base_check import BaseCheck

logger = logging.getLogger(__name__)

CHECKS_PACKAGE = "modules.scanner.active.checks"

# A check whose ``name`` is listed here is imported and available, but never
# instantiated. Keep it short and documented: an entry means "this exact
# weakness is already covered by another check".
SUPERSEDED_CHECKS = {
    # nosqli covers the same payload family as nosql_injection_active; running
    # both reports every vulnerable parameter twice.
    "nosqli": "covered by nosql_injection_active",
}


def check_classes() -> list[type[BaseCheck]]:
    """Every BaseCheck subclass defined in the checks package, deterministically ordered."""
    package = importlib.import_module(CHECKS_PACKAGE)
    found: dict[str, type[BaseCheck]] = {}
    for info in sorted(pkgutil.iter_modules(package.__path__), key=lambda i: i.name):
        if info.name.startswith("_"):
            continue
        module = importlib.import_module(f"{package.__name__}.{info.name}")
        for obj in vars(module).values():
            if (
                isinstance(obj, type)
                and issubclass(obj, BaseCheck)
                and obj is not BaseCheck
                and obj.__module__ == module.__name__
            ):
                found[f"{obj.__module__}.{obj.__name__}"] = obj
    return [found[key] for key in sorted(found)]


def active_checks() -> list[BaseCheck]:
    """Fresh instances of every enabled check, in registration order."""
    instances: list[BaseCheck] = []
    seen: dict[str, str] = {}
    for cls in check_classes():
        try:
            check = cls()
        except Exception:  # noqa: BLE001 — one broken check must not disable the scan
            logger.exception("Active check %s could not be created; skipping it", cls.__name__)
            continue
        name = str(getattr(check, "name", cls.__name__))
        if name in SUPERSEDED_CHECKS:
            logger.debug("Skipping active check %r: %s", name, SUPERSEDED_CHECKS[name])
            continue
        if name in seen:
            logger.warning(
                "Active check name %r is declared by both %s and %s; keeping the first",
                name,
                seen[name],
                cls.__name__,
            )
            continue
        seen[name] = cls.__name__
        instances.append(check)
    logger.debug("Registered %d active checks", len(instances))
    return instances
