"""Flickr API key validator."""

from ..core.base import Checker
from ._http import (
    is_valid_header_secret,
    log_invalid_input,
    log_unexpected_response,
    request_json,
)


class FlickrApiKeyChecker(Checker):
    """Validate Flickr keys with echo; its REST docs support POST form requests."""

    name = "flickr_api_key"
    description = "Validates Flickr API Keys"
    URL = "https://api.flickr.com/services/rest/"

    def check(self, secret: str) -> bool | None:
        if not is_valid_header_secret(secret):
            log_invalid_input(self.name)
            return None

        # Flickr documents POST form requests for its REST endpoint:
        # https://www.flickr.com/services/api/request.rest.html
        payload = request_json(
            self.URL,
            validator=self.name,
            data={
                "method": "flickr.test.echo",
                "api_key": secret,
                "format": "json",
                "nojsoncallback": "1",
            },
            timeout=self.timeout,
        )

        if not isinstance(payload, dict):
            log_unexpected_response(self.name)
            return None
        if payload.get("stat") == "ok":
            return True
        code = payload.get("code")
        documented_invalid_code = (type(code) is int and code == 100) or (
            type(code) is str and code == "100"
        )
        if payload.get("stat") == "fail" and documented_invalid_code:
            return False
        log_unexpected_response(self.name)
        return None
