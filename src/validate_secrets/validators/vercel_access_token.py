"""Vercel access token validator."""

from ..core.base import Checker
from ._http import is_valid_header_secret, log_invalid_input, log_unexpected_response, request_json


class VercelAccessTokenChecker(Checker):
    """Validate Vercel tokens with the user endpoint."""

    name = "vercel_access_token"
    description = "Validates Vercel Access Tokens"
    URL = "https://api.vercel.com/v2/user"

    def check(self, secret: str) -> bool | None:
        if not is_valid_header_secret(secret):
            log_invalid_input(self.name)
            return None

        payload = request_json(
            self.URL,
            validator=self.name,
            headers={"Authorization": "Bearer" + " " + secret},
            timeout=self.timeout,
        )
        user = payload.get("user") if isinstance(payload, dict) else None
        user_id = user.get("id") if isinstance(user, dict) else None
        if isinstance(user_id, str) and user_id.strip():
            return True

        log_unexpected_response(self.name)
        return None
