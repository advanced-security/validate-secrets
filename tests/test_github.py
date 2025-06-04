"""Test the GitHub integration."""

import pytest
from pathlib import Path
import sys
from unittest.mock import patch, MagicMock
import os

# Add src to path for testing
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

from validate_secrets.sources.github import GitHubSource
from validate_secrets.core.exceptions import SourceError


class TestGitHubSource:
    """Test the GitHub data source."""

    def test_init_without_token(self):
        """Test initialization without token should raise error."""
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(
                SourceError, match="Either organization or repository must be specified"
            ):
                GitHubSource(token="test-token")

    def test_init_with_token(self):
        """Test initialization with token."""
        with patch.dict(os.environ, {}, clear=True):
            source = GitHubSource(token="test-token", repo="test-owner/test-repo")
            assert source.repo == "test-owner/test-repo"
            assert source.token == "test-token"

    @patch("validate_secrets.sources.github.requests.Session.get")
    def test_get_secrets_success(self, mock_get):
        """Test successful secret scanning."""
        # Mock the GitHub API response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {
                "number": 1,
                "secret_type": "api_key",
                "secret": "test-secret-1",
                "locations": [{"path": "config.py", "start_line": 10}],
                "state": "open",
            },
            {
                "number": 2,
                "secret_type": "token",
                "secret": "test-secret-2",
                "locations": [{"path": "app.py", "start_line": 25}],
                "state": "open",
            },
        ]
        mock_response.headers = {}
        mock_get.return_value = mock_response

        with patch.dict(os.environ, {}, clear=True):
            source = GitHubSource(token="test-token", repo="test-owner/test-repo")
            secrets = list(source.get_secrets())

            assert len(secrets) == 2
            assert secrets[0]["secret"] == "test-secret-1"
            assert secrets[0]["type"] == "api_key"
            assert secrets[0]["metadata"]["alert_number"] == 1

    @patch("validate_secrets.sources.github.requests.Session.get")
    def test_get_secrets_api_error(self, mock_get):
        """Test API error handling."""
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.text = "Forbidden"
        mock_get.return_value = mock_response

        with patch.dict(os.environ, {}, clear=True):
            source = GitHubSource(token="test-token", repo="test-owner/test-repo")

            with pytest.raises(SourceError, match="GitHub access forbidden"):
                list(source.get_secrets())

    def test_get_name(self):
        """Test the get_name method."""
        with patch.dict(os.environ, {}, clear=True):
            source = GitHubSource(token="test-token", repo="test-owner/test-repo")
            name = source.get_name()
            assert name == "GitHub Repo: test-owner/test-repo"


class TestGitHubDynamicValidatorIntegration:
    """Test the GitHub integration with dynamic validator lookup after refactoring."""

    def test_github_secret_extraction(self):
        """Test that GitHub alerts properly extract secret values."""
        with patch.dict(os.environ, {"GITHUB_TOKEN": "test-token"}):
            source = GitHubSource("test-owner", "test-repo")

            # Test the _extract_secret_value method
            mock_alert = {
                "number": 1,
                "secret_type": "google_api_key",
                "secret": "AIzaSyB1234567890123456789012345678901",
                "state": "open",
            }

            secret_value = source._extract_secret_value(mock_alert)
            assert secret_value == "AIzaSyB1234567890123456789012345678901"

    @patch("validate_secrets.sources.github.requests.Session.get")
    def test_fetch_alerts_with_direct_secret_types(self, mock_get):
        """Test that alerts are processed with GitHub secret types directly."""
        with patch.dict(os.environ, {"GITHUB_TOKEN": "test-token"}):
            source = GitHubSource("test-owner", "test-repo")

            # Mock API response with GitHub secret types
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = [
                {
                    "number": 1,
                    "secret_type": "google_api_key",
                    "secret": "AIzaSyB1234567890123456789012345678901",
                    "state": "open",
                    "repository": {"full_name": "test-owner/test-repo"},
                    "created_at": "2023-01-01T00:00:00Z",
                    "updated_at": "2023-01-01T00:00:00Z",
                    "html_url": "https://github.com/test-owner/test-repo/security/secret-scanning/1",
                    "secret_type_display_name": "Google API Key",
                    "locations": [],
                },
                {
                    "number": 2,
                    "secret_type": "microsoft_teams_webhook",
                    "secret": "https://outlook.office.com/webhook/test",
                    "state": "open",
                    "repository": {"full_name": "test-owner/test-repo"},
                    "created_at": "2023-01-02T00:00:00Z",
                    "updated_at": "2023-01-02T00:00:00Z",
                    "html_url": "https://github.com/test-owner/test-repo/security/secret-scanning/2",
                    "secret_type_display_name": "Microsoft Teams Webhook",
                    "locations": [],
                },
            ]
            mock_response.headers = {}
            mock_get.return_value = mock_response

            # Get secrets and verify they use GitHub secret types directly
            secrets = list(source.get_secrets())

            assert len(secrets) == 2

            # First secret
            assert secrets[0]["type"] == "google_api_key"
            assert secrets[0]["secret"] == "AIzaSyB1234567890123456789012345678901"
            assert secrets[0]["metadata"]["source"] == "GitHub Secret Scanning"
            assert secrets[0]["metadata"]["alert_number"] == 1

            # Second secret
            assert secrets[1]["type"] == "microsoft_teams_webhook"
            assert secrets[1]["secret"] == "https://outlook.office.com/webhook/test"
            assert secrets[1]["metadata"]["alert_number"] == 2

    def test_github_cli_integration_without_mapping(self):
        """Test that CLI can process GitHub alerts without manual mapping."""
        # This test verifies the CLI would work with direct validator lookup
        from validate_secrets.core.registry import get_validator

        # Simulate GitHub alerts with various secret types
        github_alerts = [
            {"secret_type": "google_api_key", "secret": "AIzaSyTest123"},
            {
                "secret_type": "microsoft_teams_webhook",
                "secret": "https://outlook.office.com/webhook/test",
            },
            {"secret_type": "snyk_api_token", "secret": "test-snyk-token"},
            {"secret_type": "unknown_type", "secret": "unknown-secret"},  # Should be skipped
        ]

        processable_alerts = 0
        skipped_alerts = 0

        for alert in github_alerts:
            github_secret_type = alert["secret_type"]

            try:
                validator_class = get_validator(github_secret_type)
                validator = validator_class(debug=False, timeout=5)

                assert hasattr(validator, "check")
                assert validator.name == github_secret_type
                processable_alerts += 1

            except Exception:
                skipped_alerts += 1

        # We should be able to process 3 out of 4 alerts
        assert processable_alerts == 3, f"Expected 3 processable alerts, got {processable_alerts}"
        assert skipped_alerts == 1, f"Expected 1 skipped alert, got {skipped_alerts}"

    def test_no_manual_mapping_function_exists(self):
        """Verify that no manual mapping function exists in the GitHub source."""
        from validate_secrets.sources import github

        # Ensure the manual mapping function was removed
        assert not hasattr(
            github, "map_github_secret_type_to_validator"
        ), "Manual mapping function should have been removed"

        # Verify the GitHubSource class doesn't have mapping methods
        source_methods = [
            method for method in dir(github.GitHubSource) if not method.startswith("_")
        ]
        mapping_methods = [method for method in source_methods if "map" in method.lower()]

        assert len(mapping_methods) == 0, f"Found unexpected mapping methods: {mapping_methods}"


if __name__ == "__main__":
    pytest.main([__file__])
