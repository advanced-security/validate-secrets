#!/usr/bin/env python3

"""Validator for Snyk API tokens."""

import requests
import logging
from typing import Optional

from ..core.base import Checker

LOG = logging.getLogger(__name__)


class SnykAPITokenChecker(Checker):
    """Class to check if a Snyk API token is still valid."""

    name = "snyk_api_token"
    description = "Validates Snyk API tokens"

    def __init__(self, notify: bool = False, debug: bool = False, timeout: int = 30) -> None:
        super().__init__(notify, debug, timeout)
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/vnd.api+json"})
        # endpoint chosen not to return sensitive data
        self._api = "https://api.snyk.io/rest/orgs?version=2023-11-06"

    def check(self, token: str) -> Optional[bool]:
        """Check if a Snyk API token is still active."""

        if self.notify:
            LOG.debug("Cannot notify Snyk API tokens")

        try:
            request = self.session.prepare_request(
                requests.Request("GET", self._api, headers={"Authorization": f"token {token}"})
            )
            LOG.debug("Headers: %s", request.headers)
            response = self.session.send(request, timeout=self.timeout)

            LOG.debug(response.text)
            LOG.debug(response.status_code)

            if response.status_code == 200:
                return True
            elif response.status_code in (401, 403):
                return False
            else:
                LOG.error("Error for token %s: %s; %s", token, response.status_code, response.text)
                return None
        except Exception as e:
            LOG.error(f"Error for token {token}: {e}")
            return None
