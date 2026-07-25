from abc import ABC, abstractmethod
from core.events.bus import EventBus


class BaseModule(ABC):
    def __init__(self, event_bus: EventBus):
        self.event_bus = event_bus

    @abstractmethod
    def register(self):
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        pass
