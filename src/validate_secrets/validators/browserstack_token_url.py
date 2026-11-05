"""BrowserStack Automate token validator."""

import re
from urllib.parse import unquote_to_bytes

from ..core.base import Checker
from ._http import log_invalid_input, log_unexpected_response, request_json


class BrowserStackTokenUrlChecker(Checker):
    """Validate BrowserStack credentials with the read-only plan endpoint."""

    name = "browserstack_token_url"
    description = "Validates BrowserStack Automate Credentials"
    URL = "https://api.browserstack.com/automate/plan.json"

    def check(self, secret: str) -> bool | None:
        username, separator, access_key = secret.partition(":")
        if not separator or not username or not access_key:
            log_invalid_input(self.name)
            return None

        if re.search(r"%(?![0-9A-Fa-f]{2})", username) or re.search(
            r"%(?![0-9A-Fa-f]{2})", access_key
        ):
            log_invalid_input(self.name)
            return None

        try:
            username = unquote_to_bytes(username).decode("ascii")
            access_key = unquote_to_bytes(access_key).decode("ascii")
        except UnicodeError:
            log_invalid_input(self.name)
            return None

        if (
            ":" in username
            or not username.strip()
            or not access_key.strip()
            or any(ord(char) < 32 or ord(char) == 127 for char in username + access_key)
        ):
            log_invalid_input(self.name)
            return None

        payload = request_json(
            self.URL,
            validator=self.name,
            auth=(username, access_key),
            timeout=self.timeout,
        )
        if (
            isinstance(payload, dict)
            and isinstance(payload.get("automate_plan"), str)
            and payload["automate_plan"].strip()
        ):
            return True

        log_unexpected_response(self.name)
        return None
