from abc import ABC, abstractmethod
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


class BaseCheck(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        pass
