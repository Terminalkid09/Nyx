from abc import ABC, abstractmethod
from contextvars import ContextVar
from dataclasses import dataclass


@dataclass
class CheckResult:
    triggered: bool = False
    severity: str = "info"
    title: str = ""
    description: str = ""
    evidence: str | None = None
    remediation: str | None = None
    cwe: str | None = None
    # The parameter this finding belongs to, when the check knows it. Two
    # findings from the same check on different parameters are distinct: the
    # active scanner used to dedupe on (cwe, title) only and silently dropped
    # every vulnerable parameter after the first.
    param: str | None = None


# A scan-level budget for payload-driven checks. The scanner sets this before
# running the checks so the ``fast``/``balanced``/``deep`` profiles really cap
# the number of probes, not just the number of parameters.
_payload_budget: ContextVar[int | None] = ContextVar("scan_payload_budget", default=None)


def payload_budget() -> int | None:
    """Return the payload cap for the current scan (None = unlimited)."""
    return _payload_budget.get()


def set_payload_budget(limit: int | None):
    """Set the payload cap; returns the token to reset it with."""
    return _payload_budget.set(limit)


def reset_payload_budget(token) -> None:
    _payload_budget.reset(token)


def cap_payloads(payloads):
    """Slice a payload list to the current scan budget.

    Checks call this on their module-level payload lists so a depth profile
    controls real request volume. Order is preserved: the first payloads are
    the highest-signal ones by convention.
    """
    limit = payload_budget()
    if limit is None or limit <= 0:
        return payloads
    return payloads[:limit]


class BaseCheck(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        pass
