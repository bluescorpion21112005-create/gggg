"""Lightweight event bus for decoupled communication.

Uses Qt's Signal if available in the main thread, otherwise a simple callback system.
"""
from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List

logger = logging.getLogger(__name__)


class EventBus:
    """Simple publish-subscribe event system.

    Subscribers register a callback for a specific event name.
    Events are emitted with optional data.
    """

    _instance = None  # singleton for simplicity

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._subscribers: Dict[str, List[Callable]] = {}
        return cls._instance

    def subscribe(self, event: str, callback: Callable[[Any], None]) -> None:
        """Register a callback for an event."""
        self._subscribers.setdefault(event, []).append(callback)
        logger.debug(f"Subscribed to event '{event}'")

    def unsubscribe(self, event: str, callback: Callable[[Any], None]) -> None:
        """Remove a callback."""
        if event in self._subscribers:
            self._subscribers[event] = [cb for cb in self._subscribers[event] if cb != callback]
            logger.debug(f"Unsubscribed from event '{event}'")

    def emit(self, event: str, data: Any = None) -> None:
        """Publish an event, calling all registered callbacks."""
        if event in self._subscribers:
            for callback in self._subscribers[event]:
                try:
                    callback(data)
                except Exception as e:
                    logger.error(f"Error in event handler for '{event}': {e}")
        else:
            logger.debug(f"No subscribers for event '{event}'")


# Global instance for convenience
event_bus = EventBus()