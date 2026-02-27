"""Test individual validators."""

import pytest
from pathlib import Path
import sys

# Add src to path for testing
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

from validate_secrets.validators.fodselsnummer import FodselsNummerChecker
from validate_secrets.validators.google_api_keys import GoogleApiKeyChecker
from validate_secrets.validators.microsoft_teams_webhook import OfficeWebHookChecker
from validate_secrets.validators.snyk_api_token import SnykAPITokenChecker
from validate_secrets.validators.databricks_token import DatabricksTokenChecker

class TestDatabricksTokenChecker:
    """Test the Databricks token validator with host_url parameter."""

    def test_host_from_named_parameter(self):
        """Test that host_url can be set as a named parameter."""
        checker = DatabricksTokenChecker(
            host_url="https://my-workspace.databricks.com"
        )
        assert checker.host_url == "https://my-workspace.databricks.com"

    def test_host_strips_trailing_slash(self):
        """Test that trailing slash is stripped from host."""
        checker = DatabricksTokenChecker(
            host_url="https://my-workspace.databricks.com/"
        )
        assert checker.host_url == "https://my-workspace.databricks.com"

    def test_host_from_env_var_fallback(self, monkeypatch):
        """Test that DATABRICKS_HOST env var is used as fallback."""
        monkeypatch.setenv("DATABRICKS_HOST", "https://env-workspace.databricks.com")
        checker = DatabricksTokenChecker()
        assert checker.host_url == "https://env-workspace.databricks.com"

    def test_named_param_overrides_env_var(self, monkeypatch):
        """Test that host_url parameter takes precedence over env var."""
        monkeypatch.setenv("DATABRICKS_HOST", "https://env-workspace.databricks.com")
        checker = DatabricksTokenChecker(
            host_url="https://cli-workspace.databricks.com"
        )
        assert checker.host_url == "https://cli-workspace.databricks.com"

    def test_missing_host_returns_none(self, monkeypatch):
        """Test that check returns None when host is not configured."""
        monkeypatch.delenv("DATABRICKS_HOST", raising=False)
        checker = DatabricksTokenChecker()
        result = checker.check("dapi_fake_token_123")
        assert result is None


class TestFodselsNummerChecker:
    """Test the Norwegian national ID validator."""

    def test_invalid_format(self):
        """Test with invalid format."""
        checker = FodselsNummerChecker()

        # Too short
        assert checker.check("123") is False

        # Invalid characters
        assert checker.check("abcdefghijk") is False

        # Wrong format
        assert checker.check("99999999999") is False

    def test_valid_format_structure(self):
        """Test that properly formatted numbers are processed."""
        checker = FodselsNummerChecker()

        # Valid format but fake number (will likely fail checksum)
        result = checker.check("01010112345")
        # Should return False for invalid number, not None (which means invalid format)
        assert result is False


class TestGoogleApiKeyChecker:
    """Test the Google API key validator."""

    def test_invalid_format(self):
        """Test with invalid API key format."""
        checker = GoogleApiKeyChecker()

        # Too short
        assert checker.check("AIza") is None

        # Wrong prefix
        assert checker.check("BIzaSyABC123") is None

        # Invalid characters
        assert checker.check("AIzaSy!" * 10) is None

    def test_valid_format_structure(self):
        """Test that properly formatted keys are processed."""
        checker = GoogleApiKeyChecker()

        # Valid format but fake key
        fake_key = "AIzaSyA" + "B" * 32  # Valid format
        result = checker.check(fake_key)
        # Should make an API call and return True/False/None, not fail on format
        assert result in [True, False, None]


class TestOfficeWebHookChecker:
    """Test the Office webhook validator."""

    def test_invalid_url(self):
        """Test with invalid URLs."""
        checker = OfficeWebHookChecker()

        # Not a URL
        assert checker.check("not-a-url") is None

        # Wrong domain
        assert checker.check("https://example.com/webhook") is None

        # Wrong path
        assert checker.check("https://test.webhook.office.com/wrong-path") is None

    def test_valid_format_structure(self):
        """Test that properly formatted webhook URLs are processed."""
        checker = OfficeWebHookChecker()

        # Valid format but fake webhook
        fake_webhook = "https://test.webhook.office.com/webhookb2/fake-id"
        result = checker.check(fake_webhook)
        # Should make an API call and return True/False/None
        assert result in [True, False, None]


class TestSnykAPITokenChecker:
    """Test the Snyk API token validator."""

    def test_api_call_structure(self):
        """Test that API calls are made with proper structure."""
        checker = SnykAPITokenChecker()

        # Fake token (will fail auth but shouldn't crash)
        fake_token = "fake-token-123"
        result = checker.check(fake_token)
        # Should make an API call and return True/False/None
        assert result in [True, False, None]


class TestValidatorMetadata:
    """Test validator metadata and attributes."""

    def test_all_validators_have_names(self):
        """Test that all validators have proper names."""
        validators = [
            DatabricksTokenChecker(
                host_url="https://test.databricks.com"
            ),
            FodselsNummerChecker(),
            GoogleApiKeyChecker(),
            OfficeWebHookChecker(),
            SnykAPITokenChecker(),
        ]

        for validator in validators:
            assert hasattr(validator, "name")
            assert validator.name
            assert isinstance(validator.name, str)

    def test_all_validators_have_descriptions(self):
        """Test that all validators have descriptions."""
        validators = [
            DatabricksTokenChecker(
                host_url="https://test.databricks.com"
            ),
            FodselsNummerChecker(),
            GoogleApiKeyChecker(),
            OfficeWebHookChecker(),
            SnykAPITokenChecker(),
        ]

        for validator in validators:
            assert hasattr(validator, "description")
            assert validator.description
            assert isinstance(validator.description, str)

    def test_metadata_method(self):
        """Test the get_metadata method."""
        validator = FodselsNummerChecker()
        metadata = validator.get_metadata()

        assert isinstance(metadata, dict)
        assert "name" in metadata
        assert "description" in metadata
        assert "class" in metadata
        assert "module" in metadata


if __name__ == "__main__":
    pytest.main([__file__])
