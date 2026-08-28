"""Small process-local counters for bounded resource and availability telemetry."""

from __future__ import annotations

import threading
from collections.abc import Mapping


class RuntimeMetrics:
    """Store coarse counters without retaining request or transfer payloads."""

    def __init__(self) -> None:
        self._counters: dict[str, int] = {}
        self._lock = threading.Lock()

    def increment(self, name: str, amount: int = 1) -> None:
        """Increment one non-sensitive counter."""

        if not name or amount < 0:
            raise ValueError("metric name and amount must be valid")
        with self._lock:
            self._counters[name] = self._counters.get(name, 0) + amount

    def snapshot(self) -> Mapping[str, int]:
        """Return a copy suitable for diagnostics or tests."""

        with self._lock:
            return dict(self._counters)

    def value(self, name: str) -> int:
        """Return one counter value without exposing internal state."""

        with self._lock:
            return self._counters.get(name, 0)


__all__ = ["RuntimeMetrics"]
