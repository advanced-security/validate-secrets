"""LaunchDarkly access token validator."""

from .launchdarkly_api_key import LaunchDarklyApiKeyChecker


class LaunchDarklyAccessTokenChecker(LaunchDarklyApiKeyChecker):
    """Validate LaunchDarkly access tokens using the API-key endpoint."""

    name = "launchdarkly_access_token"
    description = "Validates LaunchDarkly Access Tokens"
