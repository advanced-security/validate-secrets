"""GitHub data source for secret scanning alerts."""

import requests
import logging
from typing import Iterator, Dict, Any, Optional, List
from urllib.parse import urljoin

from .base import DataSource
from ..core.exceptions import SourceError

LOG = logging.getLogger(__name__)


class GitHubSource(DataSource):
    """Data source that reads secrets from GitHub secret scanning alerts."""

    def __init__(
        self,
        token: str,
        org: str = None,
        repo: str = None,
        base_url: str = "https://api.github.com",
        state: str = "open",
        secret_type: str = None,
        validity: str = "unknown",
    ):
        """Initialize GitHub source.

        Args:
            token: GitHub personal access token
            org: Organization name (for org-level scanning)
            repo: Repository name in format "owner/repo" (for repo-level scanning)
            base_url: GitHub API base URL (for GitHub Enterprise)
            state: Filter by alert state (open, resolved)
            secret_type: Filter by specific secret type
            validity: Filter by secret validity (valid, invalid, unknown)
        """
        self.token = token
        self.org = org
        self.repo = repo
        self.base_url = base_url.rstrip("/")
        self.state = state
        self.secret_type = secret_type
        self.validity = validity

        if not (org or repo):
            raise SourceError("Either organization or repository must be specified")

        if org and repo:
            raise SourceError("Cannot specify both organization and repository")

        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            }
        )

    def get_secrets(self) -> Iterator[Dict[str, Any]]:
        """Get secrets from GitHub secret scanning alerts."""
        try:
            if self.org:
                yield from self._get_org_alerts()
            else:
                yield from self._get_repo_alerts()
        except Exception as e:
            raise SourceError(f"Failed to fetch GitHub alerts: {e}")

    def _get_org_alerts(self) -> Iterator[Dict[str, Any]]:
        """Get alerts for an organization."""
        url = f"{self.base_url}/orgs/{self.org}/secret-scanning/alerts"
        yield from self._fetch_alerts(url)

    def _get_repo_alerts(self) -> Iterator[Dict[str, Any]]:
        """Get alerts for a repository."""
        url = f"{self.base_url}/repos/{self.repo}/secret-scanning/alerts"
        yield from self._fetch_alerts(url)

    def _fetch_alerts(self, url: str) -> Iterator[Dict[str, Any]]:
        """Fetch alerts from GitHub API with pagination."""
        params = {"state": self.state, "validity": self.validity, "per_page": 100}

        if self.secret_type:
            params["secret_type"] = self.secret_type

        while url:
            LOG.debug(f"Fetching alerts from: {url}")
            response = self.session.get(url, params=params)

            if response.status_code == 401:
                raise SourceError("GitHub authentication failed. Check your token.")
            elif response.status_code == 403:
                raise SourceError("GitHub access forbidden. Check your token permissions.")
            elif response.status_code == 404:
                raise SourceError(f"GitHub resource not found. Check organization/repository name.")
            elif response.status_code != 200:
                raise SourceError(f"GitHub API error: {response.status_code} - {response.text}")

            alerts = response.json()

            for alert in alerts:
                # Extract the secret value if available
                secret_value = self._extract_secret_value(alert)
                if secret_value:
                    github_secret_type = alert.get("secret_type")

                    yield {
                        "secret": secret_value,
                        "type": github_secret_type,  # GitHub secret type - we use it directly as validator name
                        "metadata": {
                            "source": "GitHub Secret Scanning",
                            "alert_number": alert.get("number"),
                            "repository": alert.get("repository", {}).get("full_name"),
                            "state": alert.get("state"),
                            "created_at": alert.get("created_at"),
                            "updated_at": alert.get("updated_at"),
                            "url": alert.get("html_url"),
                            "locations": alert.get("locations", []),
                            "secret_type_display_name": alert.get("secret_type_display_name"),
                            "validity": alert.get("validity"),
                        },
                    }

            # Handle pagination
            url = self._get_next_page_url(response)
            params = {}  # Clear params for subsequent requests (they're in the URL)

    def _extract_secret_value(self, alert: Dict[str, Any]) -> Optional[str]:
        """Extract the secret value from a GitHub alert.

        GitHub does provide the actual secret value in API responses
        for secret scanning alerts.
        """
        return alert.get("secret")

    def _get_next_page_url(self, response: requests.Response) -> Optional[str]:
        """Extract next page URL from GitHub API response headers."""
        link_header = response.headers.get("Link", "")

        if not link_header:
            return None

        # Parse Link header to find 'next' relation
        links = {}
        for link in link_header.split(","):
            if ";" not in link:
                continue
            url_part, rel_part = link.split(";", 1)
            url = url_part.strip().strip("<>")

            rel_match = None
            for part in rel_part.split(";"):
                part = part.strip()
                if part.startswith("rel="):
                    rel_match = part.split("=", 1)[1].strip().strip("\"'")
                    break

            if rel_match:
                links[rel_match] = url

        return links.get("next")

    def get_name(self) -> str:
        """Get the name of this source."""
        if self.org:
            return f"GitHub Org: {self.org}"
        else:
            return f"GitHub Repo: {self.repo}"
