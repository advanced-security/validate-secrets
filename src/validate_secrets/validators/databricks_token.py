#!/usr/bin/env python3

"""Validator for Databricks Personal Access Tokens."""

import os
import requests
import logging
from typing import Optional

from ..core.base import Checker

LOG = logging.getLogger(__name__)


class DatabricksTokenChecker(Checker):
    """Class to check if a Databricks Personal Access Token is valid."""

    name = "databricks_token"
    description = "Validates Databricks Personal Access Tokens"

    def __init__(
        self,
        notify: bool = False,
        debug: bool = False,
        timeout: int = 30,
        host_url: Optional[str] = None,
    ) -> None:
        super().__init__(notify, debug, timeout)
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})

        # Handle host_url: strip trailing slash
        self.host_url = host_url.rstrip("/") if host_url else None

        # Fall back to DATABRICKS_HOST env var if host_url not provided
        if not self.host_url:
            env_host = os.environ.get("DATABRICKS_HOST", "").rstrip("/")
            if env_host:
                self.host_url = env_host

    def check(self, token: str) -> Optional[bool]:
        """Check if a Databricks token is still active."""
        token = token.strip()

        if not self.host_url:
            LOG.error(
                "No host URL configured. Use --host-url <url> or set DATABRICKS_HOST env var."
            )
            return None

        if self.notify:
            LOG.debug("Cannot notify Databricks tokens")

        try:
            api_url = f"{self.host_url}/api/2.0/token/list"
            request = self.session.prepare_request(
                requests.Request("GET", api_url, headers={"Authorization": f"Bearer {token}"})
            )
            LOG.debug("Request URL: %s", api_url)
            LOG.debug("Headers: %s", request.headers)
            response = self.session.send(request, timeout=self.timeout)

            LOG.debug("Response status: %s", response.status_code)
            LOG.debug("Response text: %s", response.text)

            if response.status_code == 200:
                return True
            elif response.status_code in (401, 403):
                return False
            else:
                LOG.error(
                    "Error for token %s: %s; %s",
                    token[:10] + "...",
                    response.status_code,
                    response.text,
                )
                return None
        except Exception as e:
            LOG.error("Error validating Databricks token: %s", e)
            return None
