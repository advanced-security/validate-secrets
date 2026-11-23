"""Datadog API key validator."""

import os

from ..core.base import Checker
from ._http import (
    is_valid_header_secret,
    log_invalid_configuration,
    log_invalid_input,
    log_unexpected_response,
    request_json,
)


class DatadogApiKeyChecker(Checker):
    """Validate Datadog API keys for one configured site."""

    name = "datadog_api_key"
    description = "Validates Datadog API Keys"
    SITES = {
        "datadoghq.com": "api.datadoghq.com",
        "us3.datadoghq.com": "api.us3.datadoghq.com",
        "us5.datadoghq.com": "api.us5.datadoghq.com",
        "datadoghq.eu": "api.datadoghq.eu",
        "ap1.datadoghq.com": "api.ap1.datadoghq.com",
        "ap2.datadoghq.com": "api.ap2.datadoghq.com",
        "uk1.datadoghq.com": "api.uk1.datadoghq.com",
        "ddog-gov.com": "api.ddog-gov.com",
        "us2.ddog-gov.com": "api.us2.ddog-gov.com",
    }

    def check(self, secret: str) -> bool | None:
        site = os.environ.get("DATADOG_SITE", "datadoghq.com")
        host = self.SITES.get(site)
        if host is None:
            log_invalid_configuration(self.name)
            return None
        if not is_valid_header_secret(secret):
            log_invalid_input(self.name)
            return None

        payload = request_json(
            f"https://{host}/api/v1/validate",
            validator=self.name,
            headers={"DD-API-KEY": secret},
            timeout=self.timeout,
        )
        if isinstance(payload, dict) and payload.get("valid") is True:
            return True

        log_unexpected_response(self.name)
        return None
