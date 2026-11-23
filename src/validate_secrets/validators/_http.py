"""Isolated HTTP requests for provider validators."""

import logging

import requests

LOG = logging.getLogger(__name__)


def request_json(
    url: str,
    *,
    validator: str,
    timeout: int,
    headers: dict[str, str] | None = None,
    params: dict[str, str] | None = None,
    data: dict[str, str] | None = None,
    auth: tuple[str, str] | None = None,
) -> object | None:
    """Make one isolated request and return its JSON body for HTTP 200."""
    method = "POST" if data is not None else "GET"
    try:
        with requests.Session() as session:
            session.trust_env = False
            response = session.request(
                method,
                url,
                headers=headers,
                params=params,
                data=data,
                auth=auth,
                timeout=timeout,
                allow_redirects=False,
            )
    except requests.RequestException:
        LOG.warning("%s validation request failed", validator)
        return None

    if response.status_code != 200:
        LOG.debug("%s validation returned HTTP status %s", validator, response.status_code)
        return None

    try:
        return response.json()
    except ValueError:
        LOG.warning("%s validation returned invalid JSON", validator)
        return None


def log_unexpected_response(validator: str) -> None:
    """Log a schema mismatch without exposing provider response data."""
    LOG.debug("%s validation response did not match the expected schema", validator)


def log_invalid_configuration(validator: str) -> None:
    """Log an unrecognized configured host or site without echoing its value."""
    LOG.warning("%s validation has an unsupported host or site configuration", validator)


def log_invalid_input(validator: str) -> None:
    """Log malformed secret input without including the input value."""
    LOG.debug("%s validation received malformed input", validator)


def is_valid_header_secret(secret: str) -> bool:
    """Return whether a secret is safe to use as an ASCII HTTP header value."""
    return bool(secret) and all(33 <= ord(char) <= 126 for char in secret)
