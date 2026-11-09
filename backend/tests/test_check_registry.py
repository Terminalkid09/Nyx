"""The active-check registry is the only place scope is decided."""
from modules.scanner.active import registry
from modules.scanner.active.registry import active_checks, check_classes
from modules.scanner.active.scanner import ActiveScanner
from modules.scanner.base_check import BaseCheck


def test_registry_finds_every_check_in_the_package():
    classes = check_classes()

    assert len(classes) >= 130, f"only {len(classes)} check classes discovered"
    assert all(issubclass(cls, BaseCheck) for cls in classes)
    # Spot-check families that were previously hand-imported.
    names = {cls.__name__ for cls in classes}
    assert {"SQLiCheck", "XssCheck", "SsrfCheck", "ActiveLog4shellCheck"} <= names


def test_discovery_order_is_deterministic():
    first = [cls.__name__ for cls in check_classes()]
    second = [cls.__name__ for cls in check_classes()]

    assert first == second
    assert first == sorted(first, key=lambda name: (next(
        cls.__module__ for cls in check_classes() if cls.__name__ == name
    ), name))


def test_instances_have_unique_names():
    names = [check.name for check in active_checks()]

    assert len(names) == len(set(names))
    assert len(names) >= 130


def test_superseded_check_is_not_instantiated():
    names = {check.name for check in active_checks()}

    assert "active_nosql_injection" in names
    assert "nosqli" not in names


def test_scanner_uses_the_registry():
    scanner = ActiveScanner()

    assert [check.name for check in scanner.checks] == [
        check.name for check in active_checks()
    ]
    # The list is cached on the instance, not rebuilt on every access.
    assert scanner.checks is scanner.checks


def test_a_broken_check_is_skipped_instead_of_breaking_the_scan(monkeypatch):
    class BrokenCheck(BaseCheck):
        name = "broken"

        def __init__(self):
            raise RuntimeError("boom")

        async def run(self, base_request, target_params):
            return []

    healthy = active_checks()[0]
    monkeypatch.setattr(registry, "check_classes", lambda: [BrokenCheck, type(healthy)])

    result = active_checks()

    assert [check.name for check in result] == [healthy.name]


def test_duplicate_names_keep_the_first(monkeypatch):
    class First(BaseCheck):
        name = "same"

        async def run(self, base_request, target_params):
            return []

    class Second(BaseCheck):
        name = "same"

        async def run(self, base_request, target_params):
            return []

    monkeypatch.setattr(registry, "check_classes", lambda: [First, Second])

    result = active_checks()

    assert [type(check) for check in result] == [First]
