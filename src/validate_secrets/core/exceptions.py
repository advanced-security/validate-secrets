"""Custom exceptions for validate-secrets."""


class ValidateSecretsError(Exception):
    """Base exception for validate-secrets."""

    pass


class ValidatorError(ValidateSecretsError):
    """Error occurred during secret validation."""

    pass


class SourceError(ValidateSecretsError):
    """Error occurred while reading from a source."""

    pass


class ConfigurationError(ValidateSecretsError):
    """Error in configuration."""

    pass


class ValidationTimeoutError(ValidatorError):
    """Validation timed out."""

    pass
