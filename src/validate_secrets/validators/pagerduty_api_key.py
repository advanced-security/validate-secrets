"""PagerDuty API key validator."""

import os

from ..core.base import Checker
from ._http import (
    is_valid_header_secret,
    log_invalid_configuration,
    log_invalid_input,
    log_unexpected_response,
    request_json,
)


class PagerDutyApiKeyChecker(Checker):
    """Validate PagerDuty API keys for one configured region."""

    name = "pagerduty_api_key"
    description = "Validates PagerDuty API Keys"
    HOSTS = {
        "api.pagerduty.com",
        "api.eu.pagerduty.com",
    }
    URL_PATH = "/abilities"
    ACCEPT = "application/vnd.pagerduty+json;version=2"

    def check(self, secret: str) -> bool | None:
        host = os.environ.get("PAGERDUTY_HOST", "api.pagerduty.com")
        if host not in self.HOSTS:
            log_invalid_configuration(self.name)
            return None
        if not is_valid_header_secret(secret):
            log_invalid_input(self.name)
            return None

        payload = request_json(
            f"https://{host}{self.URL_PATH}",
            validator=self.name,
            headers={
                "Authorization": f"Token token={secret}",
                "Accept": self.ACCEPT,
            },
            timeout=self.timeout,
        )
        abilities = payload.get("abilities") if isinstance(payload, dict) else None
        if isinstance(abilities, list) and all(isinstance(ability, str) for ability in abilities):
            return True

        log_unexpected_response(self.name)
        return None
