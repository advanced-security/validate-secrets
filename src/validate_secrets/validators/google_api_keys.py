#!/usr/bin/env python3

"""Validator for Google API Keys."""

import re
import requests
import logging
from typing import Optional

from ..core.base import Checker

LOG = logging.getLogger(__name__)

GOOGLE_API_KEY_RE = re.compile(r"^AIza[A-Za-z0-9-_]{35}$")
GOOGLE_MAPS_URL = "https://maps.googleapis.com/maps/api/geocode/json?address=1600+Amphitheatre+Parkway,+Mountain+View,+CA&key="
GOOGLE_API_DENIED_STATUS = "REQUEST_DENIED"
GOOGLE_API_INVALID_KEY_MESSAGE = "The provided API key is invalid. "
GOOGLE_API_PROJECT_NOT_AUTHORIZED_MESSAGE = "This API project is not authorized to use this API."


class GoogleApiKeyChecker(Checker):
    """Class to check if a Google API Key is valid."""

    name = "google_api_key"  # Match GitHub secret type exactly
    description = "Validates Google API Keys"

    def __init__(self, notify: bool = False, debug: bool = False, timeout: int = 30) -> None:
        super().__init__(notify, debug, timeout)
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})

    def check(self, key: str) -> Optional[bool]:
        """Check if a Google API Key is valid."""
        key = key.rstrip()

        # check the format against the regex
        if not GOOGLE_API_KEY_RE.match(key):
            LOG.error("Invalid format for Google API key")
            return None

        if self.notify:
            LOG.debug("Cannot notify Google API keys")

        try:
            # check the key against the Google Maps API
            # no need to URL encode the key, since we know it is already URL safe, having verified it with the regex
            response = requests.get(GOOGLE_MAPS_URL + key, timeout=self.timeout)

            if response.status_code == 200:
                data = response.json()
                if data["status"] == GOOGLE_API_DENIED_STATUS:
                    if data["error_message"] == GOOGLE_API_INVALID_KEY_MESSAGE:
                        # it's definitely invalid
                        return False
                    elif data["error_message"] == GOOGLE_API_PROJECT_NOT_AUTHORIZED_MESSAGE:
                        # it's valid, but we don't know which Google API it's for - it's not Google Maps
                        return True
                    else:
                        # some other error, we return an error
                        LOG.warning(
                            f'Unexpected error message for key {key}: {data["error_message"]}'
                        )
                        return None
                return True
        except Exception as e:
            LOG.error(f"Error for key {key}: {e}")
            return None

        return None
