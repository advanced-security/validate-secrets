"""Test the plugin registry system."""

import pytest
from pathlib import Path
import sys

# Add src to path for testing
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

from validate_secrets.core.registry import (
    ValidatorRegistry,
    get_validators,
    get_validator,
    list_validators,
)
from validate_secrets.core.base import Checker
from validate_secrets.core.exceptions import ValidatorError


class TestValidatorRegistry:
    """Test cases for ValidatorRegistry."""

    def test_load_validators(self):
        """Test that validators are loaded correctly."""
        registry = ValidatorRegistry()
        validators = registry.load_validators()

        assert len(validators) > 0
        assert "fodselsnummer" in validators
        assert "google_api_key" in validators
        assert "microsoft_teams_webhook" in validators
        assert "snyk_api_token" in validators

    def test_get_validator(self):
        """Test getting a specific validator."""
        registry = ValidatorRegistry()
        validator_class = registry.get_validator("fodselsnummer")

        assert validator_class is not None
        assert issubclass(validator_class, Checker)

    def test_get_unknown_validator(self):
        """Test error handling for unknown validator."""
        registry = ValidatorRegistry()

        with pytest.raises(ValidatorError):
            registry.get_validator("unknown_validator")

    def test_list_validators(self):
        """Test listing validators."""
        registry = ValidatorRegistry()
        validator_names = registry.list_validators()

        assert isinstance(validator_names, list)
        assert len(validator_names) > 0
        assert "fodselsnummer" in validator_names


class TestDynamicGitHubValidatorMapping:
    """Test dynamic GitHub secret type to validator mapping functionality."""

    def test_github_secret_type_direct_lookup(self):
        """Test that GitHub secret types can be used directly as validator names."""
        github_secret_types = ["google_api_key", "microsoft_teams_webhook"]

        successful_matches = 0

        for secret_type in github_secret_types:
            try:
                validator_class = get_validator(secret_type)
                validator = validator_class()
                assert validator is not None
                assert hasattr(validator, "check")
                successful_matches += 1
            except Exception as e:
                pytest.fail(f"Failed to get validator for {secret_type}: {e}")

        assert successful_matches == len(
            github_secret_types
        ), f"Expected {len(github_secret_types)} matches, got {successful_matches}"

    def test_unknown_github_secret_types(self):
        """Test that unknown GitHub secret types raise appropriate errors."""
        unknown_types = [
            "unknown_secret_type",
            "another_key",
        ]

        for secret_type in unknown_types:
            with pytest.raises(ValidatorError, match="Unknown validator"):
                get_validator(secret_type)

    def test_github_alert_processing_workflow(self):
        """Test the complete GitHub alert processing workflow with dynamic lookup."""
        mock_alerts = [
            {
                "number": 1,
                "secret_type": "google_api_key",
                "secret": "AIzaSyB1234567890123456789012345678901",
                "state": "open",
            },
            {
                "number": 2,
                "secret_type": "microsoft_teams_webhook",
                "secret": "https://outlook.office.com/webhook/test-webhook-url",
                "state": "open",
            },
            {
                "number": 3,
                "secret_type": "snyk_api_token",
                "secret": "a1b2c3d4-e5f6-g7h8-i9j0-k1l2m3n4o5p6",
                "state": "open",
            },
        ]

        validated_alerts = 0

        for alert in mock_alerts:
            secret_type = alert["secret_type"]
            secret = alert["secret"]

            # Test direct lookup using GitHub secret type (no mapping needed)
            validator_class = get_validator(secret_type)
            validator = validator_class(debug=False, timeout=5)

            assert validator is not None
            assert hasattr(validator, "check")
            assert hasattr(validator, "name")
            validated_alerts += 1

        assert validated_alerts == len(
            mock_alerts
        ), f"Expected to validate {len(mock_alerts)} alerts, validated {validated_alerts}"

    def test_mixed_alert_processing_with_unknown_types(self):
        """Test processing mixed alerts including unknown secret types."""
        mixed_alerts = [
            {
                "number": 1,
                "secret_type": "google_api_key",  # Known validator
                "secret": "AIzaSyB1234567890123456789012345678901",
                "state": "open",
            },
            {
                "number": 2,
                "secret_type": "mailchimp_api_key",  # Unknown validator
                "secret": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6-us2",
                "state": "open",
            },
            {
                "number": 3,
                "secret_type": "snyk_api_token",  # Known validator
                "secret": "a1b2c3d4-e5f6-g7h8-i9j0-k1l2m3n4o5p6",
                "state": "open",
            },
        ]

        validated_count = 0
        no_validator_count = 0

        for alert in mixed_alerts:
            secret_type = alert["secret_type"]

            try:
                validator_class = get_validator(secret_type)
                validator = validator_class()
                assert validator is not None
                validated_count += 1
            except ValidatorError as e:
                assert "Unknown validator" in str(e)
                no_validator_count += 1

        assert validated_count == 2, f"Expected 2 validated alerts, got {validated_count}"
        assert no_validator_count == 1, f"Expected 1 unknown validator, got {no_validator_count}"

    def test_validator_name_consistency(self):
        """Test that validator names match their expected GitHub secret types."""
        expected_mappings = {
            "google_api_key": "google_api_key",
            "microsoft_teams_webhook": "microsoft_teams_webhook",
            "snyk_api_token": "snyk_api_token",
        }

        for github_type, expected_name in expected_mappings.items():
            validator_class = get_validator(github_type)
            validator = validator_class()

            # The validator's name should match the GitHub secret type
            assert (
                validator.name == expected_name
            ), f"Expected validator name '{expected_name}', got '{validator.name}'"

    def test_registry_integration(self):
        """Test that the registry properly integrates with dynamic lookup."""
        # Get all available validators
        available_validators = list_validators()

        # Ensure our GitHub-compatible validators are present
        expected_github_types = ["google_api_key", "microsoft_teams_webhook", "snyk_api_token"]

        for github_type in expected_github_types:
            assert (
                github_type in available_validators
            ), f"GitHub secret type '{github_type}' not found in available validators"

        # Test that we can instantiate each one
        for github_type in expected_github_types:
            validator_class = get_validator(github_type)
            validator = validator_class()
            assert hasattr(
                validator, "check"
            ), f"Validator for '{github_type}' missing check method"

    def test_get_validator_info(self):
        """Test getting validator metadata."""
        registry = ValidatorRegistry()
        info = registry.get_validator_info()

        assert isinstance(info, dict)
        assert len(info) > 0
        assert "fodselsnummer" in info

        fodsel_info = info["fodselsnummer"]
        assert "name" in fodsel_info
        assert "description" in fodsel_info
        assert "class" in fodsel_info


class TestGlobalFunctions:
    """Test global registry functions."""

    def test_get_validators(self):
        """Test the global get_validators function."""
        validators = get_validators()
        assert len(validators) > 0

    def test_get_validator(self):
        """Test the global get_validator function."""
        validator_class = get_validator("fodselsnummer")
        assert issubclass(validator_class, Checker)

    def test_list_validators(self):
        """Test the global list_validators function."""
        names = list_validators()
        assert len(names) > 0
        assert "fodselsnummer" in names


class TestValidatorInstantiation:
    """Test that validators can be instantiated and used."""

    def test_instantiate_fodselsnummer(self):
        """Test instantiating the fodselsnummer validator."""
        validator_class = get_validator("fodselsnummer")
        validator = validator_class()

        assert validator is not False
        assert hasattr(validator, "check")

        result = validator.check("invalid")
        assert result is False

    def test_instantiate_all_validators(self):
        """Test that all validators can be instantiated."""
        validators = get_validators()

        for name, validator_class in validators.items():
            validator = validator_class()
            assert validator is not None
            assert hasattr(validator, "check")
            assert callable(validator.check)


if __name__ == "__main__":
    pytest.main([__file__])
