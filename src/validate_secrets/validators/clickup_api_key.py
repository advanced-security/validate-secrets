"""ClickUp API key validator."""

from ..core.base import Checker
from ._http import is_valid_header_secret, log_invalid_input, log_unexpected_response, request_json


class ClickUpApiKeyChecker(Checker):
    """Validate ClickUp API keys with the authorized-user endpoint."""

    name = "clickup_api_key"
    description = "Validates ClickUp API Keys"
    URL = "https://api.clickup.com/api/v2/user"

    def check(self, secret: str) -> bool | None:
        if not is_valid_header_secret(secret):
            log_invalid_input(self.name)
            return None

        payload = request_json(
            self.URL,
            validator=self.name,
            headers={"Authorization": secret},
            timeout=self.timeout,
        )
        user = payload.get("user") if isinstance(payload, dict) else None
        user_id = user.get("id") if isinstance(user, dict) else None
        if isinstance(user_id, int) and not isinstance(user_id, bool) and user_id > 0:
            return True

        log_unexpected_response(self.name)
        return None
