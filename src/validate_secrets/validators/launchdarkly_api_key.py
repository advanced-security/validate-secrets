"""LaunchDarkly API key validator."""

import os

from ..core.base import Checker
from ._http import (
    is_valid_header_secret,
    log_invalid_configuration,
    log_invalid_input,
    log_unexpected_response,
    request_json,
)


class LaunchDarklyApiKeyChecker(Checker):
    """Validate LaunchDarkly API keys on one configured host."""

    name = "launchdarkly_api_key"
    description = "Validates LaunchDarkly API Keys"
    HOSTS = {
        "app.launchdarkly.com",
        "app.eu.launchdarkly.com",
        "app.launchdarkly.us",
    }
    URL_PATH = "/api/v2/caller-identity"

    def check(self, secret: str) -> bool | None:
        host = os.environ.get("LAUNCHDARKLY_HOST", "app.launchdarkly.com")
        if host not in self.HOSTS:
            log_invalid_configuration(self.name)
            return None
        if not secret.startswith("api-") or not secret[len("api-") :].strip():
            log_invalid_input(self.name)
            return None
        if not is_valid_header_secret(secret):
            log_invalid_input(self.name)
            return None

        identity = request_json(
            f"https://{host}{self.URL_PATH}",
            validator=self.name,
            headers={"Authorization": secret},
            timeout=self.timeout,
        )
        if isinstance(identity, dict) and isinstance(identity.get("accountId"), str):
            if identity["accountId"].strip():
                return True

        log_unexpected_response(self.name)
        return None
