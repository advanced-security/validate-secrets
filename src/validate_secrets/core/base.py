"""Base classes for validators."""

import logging
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
import signal
import functools

from .exceptions import ValidationTimeoutError

LOG = logging.getLogger(__name__)


def timeout_handler(signum, frame):
    """Signal handler for validation timeouts."""
    raise ValidationTimeoutError("Validation timed out")


def with_timeout(timeout_seconds: int = 30):
    """Decorator to add timeout to validation methods."""

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Set up timeout signal
            old_handler = signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(timeout_seconds)

            try:
                result = func(*args, **kwargs)
                return result
            finally:
                # Clean up timeout signal
                signal.alarm(0)
                signal.signal(signal.SIGALRM, old_handler)

        return wrapper

    return decorator


class Checker(ABC):
    """Base class for all secret validators.

    Validators should inherit from this class and implement the check method.
    """

    # Validator metadata (can be overridden in subclasses)
    name: str = ""
    description: str = ""

    def __init__(self, notify: bool = False, debug: bool = False, timeout: int = 30) -> None:
        """Initialize the checker.

        Args:
            notify: Whether to send notifications to endpoints
            debug: Enable debug logging
            timeout: Timeout in seconds for validation
        """
        self.notify = notify
        self.debug = debug
        self.timeout = timeout

        if self.debug:
            logging.getLogger().setLevel(logging.DEBUG)

    @abstractmethod
    def check(self, secret: str) -> Optional[bool]:
        """Check if a secret is valid.

        Args:
            secret: The secret string to validate

        Returns:
            True if valid, False if invalid, None if error/unknown
        """
        pass

    def get_metadata(self) -> Dict[str, Any]:
        """Get validator metadata."""
        return {
            "name": self.name or self.__class__.__name__.lower().replace("checker", ""),
            "description": self.description or f"Validates {self.name or 'secrets'}",
            "class": self.__class__.__name__,
            "module": self.__module__,
        }

    def __str__(self) -> str:
        return self.name or self.__class__.__name__

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(notify={self.notify}, debug={self.debug})"
