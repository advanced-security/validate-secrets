"""Base class for data sources."""

from abc import ABC, abstractmethod
from typing import Iterator, Dict, Any, Optional


class DataSource(ABC):
    """Abstract base class for all data sources."""

    @abstractmethod
    def get_secrets(self) -> Iterator[Dict[str, Any]]:
        """Get secrets from the source.

        Yields:
            Dict containing at least:
            - 'secret': The secret string
            - 'type': Optional secret type hint
            - 'metadata': Optional additional metadata
        """
        pass

    @abstractmethod
    def get_name(self) -> str:
        """Get a human-readable name for this source."""
        pass
