"""Abstract M7 Client Interface for M6."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict


class M7ClientInterface(ABC):
    @abstractmethod
    def fetch_analysis(self, analysis_id: str) -> Dict[str, Any]:
        """Fetch full analysis document from M7."""
        pass

    @abstractmethod
    def submit_section(self, analysis_id: str, section: str, payload: Any) -> Dict[str, Any]:
        """Submit an owned section (response_actions) to M7."""
        pass

    @abstractmethod
    def emit_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Submit a pipeline event (response.done) to M7."""
        pass
