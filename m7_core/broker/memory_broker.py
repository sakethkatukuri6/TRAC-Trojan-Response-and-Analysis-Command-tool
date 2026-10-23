"""In-memory fake broker adapter for testing and deterministic local dispatch."""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Callable, Dict, List
from m7_core.broker.interface import BrokerAdapter


class MemoryBroker(BrokerAdapter):
    def __init__(self):
        self.published_events: List[Dict[str, Any]] = []
        self.subscribers: Dict[str, List[Callable[[Dict[str, Any]], None]]] = defaultdict(list)

    def publish(self, topic: str, event: Dict[str, Any]) -> None:
        self.published_events.append({"topic": topic, "event": event})
        for handler in self.subscribers.get(topic, []):
            handler(event)
        for handler in self.subscribers.get("*", []):
            handler(event)

    def subscribe(self, topic: str, handler: Callable[[Dict[str, Any]], None]) -> None:
        self.subscribers[topic].append(handler)

    def clear(self) -> None:
        self.published_events.clear()
        self.subscribers.clear()
