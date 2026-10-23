"""Abstract Broker Adapter Interface."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, List


class BrokerAdapter(ABC):
    @abstractmethod
    def publish(self, topic: str, event: Dict[str, Any]) -> None:
        pass

    @abstractmethod
    def subscribe(self, topic: str, handler: Callable[[Dict[str, Any]], None]) -> None:
        pass
