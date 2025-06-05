"""Test data sources."""

import pytest
import json
import csv
from pathlib import Path
import tempfile
import sys

# Add src to path for testing
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

from validate_secrets.sources.file import FileSource
from validate_secrets.core.exceptions import SourceError


class TestFileSource:
    """Test the file data source."""

    def test_text_file(self):
        """Test reading from text file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("secret1\n")
            f.write("secret2\n")
            f.write("# comment\n")
            f.write("\n")  # empty line
            f.write("secret3\n")
            temp_path = f.name

        try:
            source = FileSource(temp_path, "text", "test_type")
            secrets = list(source.get_secrets())

            assert len(secrets) == 3
            assert secrets[0]["secret"] == "secret1"
            assert secrets[1]["secret"] == "secret2"
            assert secrets[2]["secret"] == "secret3"

            # Check metadata
            assert secrets[0]["metadata"]["line"] == 1
            assert secrets[0]["metadata"]["source"] == temp_path

        finally:
            Path(temp_path).unlink()

    def test_csv_file(self):
        """Test reading from CSV file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            writer = csv.writer(f)
            writer.writerow(["secret", "type"])
            writer.writerow(["secret1", "api_key"])
            writer.writerow(["secret2", "token"])
            temp_path = f.name

        try:
            source = FileSource(temp_path, "csv")
            secrets = list(source.get_secrets())

            assert len(secrets) == 2
            assert secrets[0]["secret"] == "secret1"
            assert secrets[1]["secret"] == "secret2"
            assert secrets[0]["type"] == "api_key"

            # Check metadata
            assert secrets[0]["metadata"]["row"] == 2
            assert "csv_data" in secrets[0]["metadata"]

        finally:
            Path(temp_path).unlink()

    def test_json_file_list(self):
        """Test reading from JSON file with list format."""
        test_data = ["secret1", "secret2", "secret3"]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(test_data, f)
            temp_path = f.name

        try:
            source = FileSource(temp_path, "json", "test_type")
            secrets = list(source.get_secrets())

            assert len(secrets) == 3
            assert secrets[0]["secret"] == "secret1"
            assert secrets[0]["type"] == "test_type"
            assert secrets[0]["metadata"]["index"] == 0

        finally:
            Path(temp_path).unlink()

    def test_json_file_objects(self):
        """Test reading from JSON file with object format."""
        test_data = [
            {"secret": "secret1", "type": "api_key"},
            {"secret": "secret2", "type": "token"},
        ]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(test_data, f)
            temp_path = f.name

        try:
            source = FileSource(temp_path, "json")
            secrets = list(source.get_secrets())

            assert len(secrets) == 2
            assert secrets[0]["secret"] == "secret1"
            assert secrets[0]["type"] == "api_key"
            assert secrets[1]["type"] == "token"

        finally:
            Path(temp_path).unlink()

    def test_nonexistent_file(self):
        """Test error handling for nonexistent file."""
        with pytest.raises(SourceError):
            FileSource("/nonexistent/file.txt")

    def test_unsupported_format(self):
        """Test error handling for unsupported format."""
        with tempfile.NamedTemporaryFile() as f:
            with pytest.raises(SourceError):
                FileSource(f.name, "unsupported_format")

    def test_get_name(self):
        """Test the get_name method."""
        with tempfile.NamedTemporaryFile() as f:
            source = FileSource(f.name, "text")
            name = source.get_name()
            assert name.startswith("File:")
            assert Path(f.name).name in name


if __name__ == "__main__":
    pytest.main([__file__])
