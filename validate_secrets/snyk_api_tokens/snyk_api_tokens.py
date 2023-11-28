#!/usr/bin/env python3

"""Check Snyk API tokens."""

import requests
from urllib3.util.url import parse_url
from typing import Optional
import logging


LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


class SnykAPITokenChecker:
    """Class to check if a Snyk API token is still valid."""
    def __init__(self, notify: bool=False, debug=False) -> None:
        self.session = requests.Session()
        self.session.headers.update({'Content-Type': 'application/vnd.api+json'})
        self.notify = notify

        # endpoint chosen not to return sensitive data
        self._api = 'https://api.snyk.io/rest/orgs?version=2023-11-06'

        if debug:
            LOG.setLevel(logging.DEBUG)

    def check(self, token) -> Optional[bool]:
        """Check if a Snyk API token is still valid."""

        if self.notify:
            LOG.debug("Cannot notify Snyk API tokens")

        request = self.session.prepare_request(requests.Request('GET', self._api, headers={'Authorization': f'token {token}'}))
        LOG.debug("Headers: %s", request.headers)
        response = self.session.send(request)

        LOG.debug(response.text)
        LOG.debug(response.status_code)

        if response.status_code == 200:
            return True
        elif response.status_code in (401, 403):
            return False
        else:
            LOG.error('Error for token %s: %s; %s', token, response.status_code, response.text)
            return None
