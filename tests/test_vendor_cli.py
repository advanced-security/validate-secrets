"""CLI smoke tests for vendor validators."""

import json

import pytest
import requests
from click.testing import CliRunner
from requests import Response

from validate_secrets.cli import cli


def json_response(status_code: int, payload: object) -> Response:
    response = Response()
    response.status_code = status_code
    response.headers["Content-Type"] = "application/json"
    response._content = json.dumps(payload).encode("utf-8")
    return response


def test_list_validators_command_includes_vendor_types() -> None:
    result = CliRunner().invoke(cli, ["list-validators"], terminal_width=160)

    assert result.exit_code == 0
    for name in (
        "flickr_api_key",
        "clickup_api_key",
        "vercel_access_token",
        "vercel_cli_token",
        "datadog_api_key",
        "pagerduty_api_key",
        "browserstack_token_url",
    ):
        assert name in result.output
    assert "launchdarkly" in result.output


def test_validate_command_uses_checker_and_reports_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def request(session: requests.Session, method: str, url: str, **kwargs: object) -> Response:
        captured.update(method=method, url=url, kwargs=kwargs)
        return json_response(200, {"user": {"id": 123, "username": "synthetic"}})

    monkeypatch.setattr(requests.Session, "request", request)
    result = CliRunner().invoke(
        cli,
        [
            "validate",
            "pk_1234567_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456",
            "clickup_api_key",
        ],
    )

    assert result.exit_code == 0
    assert "Secret is valid" in result.output
    assert captured["method"] == "GET"
    assert captured["url"] == "https://api.clickup.com/api/v2/user"
    kwargs = captured["kwargs"]
    assert isinstance(kwargs, dict)
    assert kwargs["headers"]["Authorization"] == "pk_1234567_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
    assert kwargs["allow_redirects"] is False
