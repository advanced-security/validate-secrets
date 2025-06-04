"""File-based data source."""

import csv
import json
from pathlib import Path
from typing import Iterator, Dict, Any

from .base import DataSource
from ..core.exceptions import SourceError


class FileSource(DataSource):
    """Data source that reads secrets from files."""

    def __init__(self, file_path: str, file_format: str = "text", secret_type: str = None):
        """Initialize file source.

        Args:
            file_path: Path to the file
            file_format: Format of the file (text, csv, json)
            secret_type: Optional hint for the type of secrets in the file
        """
        self.file_path = Path(file_path)
        self.file_format = file_format.lower()
        self.secret_type = secret_type

        if not self.file_path.exists():
            raise SourceError(f"File not found: {file_path}")

        if self.file_format not in ("text", "csv", "json"):
            raise SourceError(f"Unsupported file format: {file_format}")

    def get_secrets(self) -> Iterator[Dict[str, Any]]:
        """Get secrets from the file."""
        try:
            if self.file_format == "text":
                yield from self._read_text()
            elif self.file_format == "csv":
                yield from self._read_csv()
            elif self.file_format == "json":
                yield from self._read_json()
        except Exception as e:
            raise SourceError(f"Failed to read file {self.file_path}: {e}")

    def _read_text(self) -> Iterator[Dict[str, Any]]:
        """Read secrets from a plain text file (one per line)."""
        with open(self.file_path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                yield {
                    "secret": line,
                    "type": self.secret_type,
                    "metadata": {"source": str(self.file_path), "line": line_num},
                }

    def _read_csv(self) -> Iterator[Dict[str, Any]]:
        """Read secrets from a CSV file."""
        with open(self.file_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)

            for row_num, row in enumerate(reader, 2):  # skip header row
                secret = row.get("secret") or row.get("Secret")
                if not secret:
                    # Try to find the first non-empty column
                    secret = next((v for v in row.values() if v), None)

                if not secret:
                    continue

                secret_type = row.get("type") or row.get("Type") or self.secret_type

                yield {
                    "secret": secret.strip(),
                    "type": secret_type,
                    "metadata": {"source": str(self.file_path), "row": row_num, "csv_data": row},
                }

    def _read_json(self) -> Iterator[Dict[str, Any]]:
        """Read secrets from a JSON file."""
        with open(self.file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if isinstance(data, list):
            # List of secrets or secret objects
            for i, item in enumerate(data):
                if isinstance(item, str):
                    yield {
                        "secret": item,
                        "type": self.secret_type,
                        "metadata": {"source": str(self.file_path), "index": i},
                    }
                elif isinstance(item, dict):
                    secret = item.get("secret") or item.get("value")
                    if secret:
                        yield {
                            "secret": secret,
                            "type": item.get("type") or self.secret_type,
                            "metadata": {
                                "source": str(self.file_path),
                                "index": i,
                                "json_data": item,
                            },
                        }
        elif isinstance(data, dict):
            # Single object with secrets
            if "secrets" in data:
                for i, secret in enumerate(data["secrets"]):
                    if isinstance(secret, str):
                        yield {
                            "secret": secret,
                            "type": self.secret_type,
                            "metadata": {"source": str(self.file_path), "index": i},
                        }

    def get_name(self) -> str:
        """Get the name of this source."""
        return f"File: {self.file_path.name}"
