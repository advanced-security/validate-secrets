"""Offline tests for vendor API validators."""

import base64
import http.server
import json
import logging
import re
import threading
from urllib.parse import parse_qs

import pytest
import requests
from requests.adapters import HTTPAdapter
from requests.exceptions import SSLError
from requests.models import Response

from validate_secrets.core.base import Checker
from validate_secrets.validators.browserstack_token_url import BrowserStackTokenUrlChecker
from validate_secrets.validators.clickup_api_key import ClickUpApiKeyChecker
from validate_secrets.validators.datadog_api_key import DatadogApiKeyChecker
from validate_secrets.validators.flickr_api_key import FlickrApiKeyChecker
from validate_secrets.validators.launchdarkly_access_token import LaunchDarklyAccessTokenChecker
from validate_secrets.validators.launchdarkly_api_key import LaunchDarklyApiKeyChecker
from validate_secrets.validators.pagerduty_api_key import PagerDutyApiKeyChecker
from validate_secrets.validators.vercel_access_token import VercelAccessTokenChecker
from validate_secrets.validators.vercel_cli_token import VercelCliTokenChecker

FLICKR_KEY = "abcdef0123456789abcdef0123456789"
CLICKUP_KEY = "pk_1234567_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
VERCEL_TOKEN = "aaaaaaaaaaaaaaaaaaaaaaaa"
DATADOG_KEY = "deadbeefcafebabefeedface01234567"
LAUNCHDARKLY_KEY = "api-00000000-0000-0000-0000-000000000000"
LAUNCHDARKLY_ALIAS_KEY = "api-11111111-1111-1111-1111-111111111111"
PAGERDUTY_KEY = "AAAAAAAAAAAAAAAAAAAa"
BROWSERSTACK_USER = "synthetic_user"
BROWSERSTACK_KEY = "AbCdEf0123456789GhIj"
BROWSERSTACK_SECRET = f"{BROWSERSTACK_USER}:{BROWSERSTACK_KEY}"


class FakeResponse:
    def __init__(self, status_code: int, payload: object) -> None:
        self.status_code = status_code
        self.payload = payload

    def json(self) -> object:
        if isinstance(self.payload, Exception):
            raise self.payload
        return self.payload


def mock_http(
    monkeypatch: pytest.MonkeyPatch,
    response: FakeResponse | None = None,
    error: Exception | None = None,
) -> list[tuple[requests.Session, str, str, dict[str, object]]]:
    calls: list[tuple[requests.Session, str, str, dict[str, object]]] = []

    def request(
        session: requests.Session, method: str, url: str, **kwargs: object
    ) -> FakeResponse | None:
        calls.append((session, method, url, kwargs))
        if error is not None:
            raise error
        return response

    monkeypatch.setattr(requests.Session, "request", request)
    return calls


def install_adapter(
    monkeypatch: pytest.MonkeyPatch,
    *,
    payload: object | None = None,
    status_code: int = 200,
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    error: requests.RequestException | None = None,
) -> list[tuple[requests.PreparedRequest, dict[str, object]]]:
    prepared: list[tuple[requests.PreparedRequest, dict[str, object]]] = []

    def send(adapter: HTTPAdapter, request: requests.PreparedRequest, **kwargs: object) -> Response:
        prepared.append((request, kwargs))
        if error is not None:
            raise error
        response = Response()
        response.status_code = status_code
        response.headers["Content-Type"] = "application/json"
        response.headers.update(headers or {})
        response._content = body if body is not None else json.dumps(payload).encode("utf-8")
        response.request = request
        response.url = request.url
        return response

    monkeypatch.setattr(HTTPAdapter, "send", send)
    return prepared


@pytest.fixture(autouse=True)
def clear_vendor_host_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("DATADOG_SITE", "LAUNCHDARKLY_HOST", "PAGERDUTY_HOST"):
        monkeypatch.delenv(name, raising=False)


CHECKS: list[tuple[type[Checker], str, str, dict[str, str] | None, object]] = [
    (
        FlickrApiKeyChecker,
        FLICKR_KEY,
        "https://api.flickr.com/services/rest/",
        None,
        {
            "stat": "ok",
            "api_key": FLICKR_KEY,
            "method": "flickr.test.echo",
            "format": "json",
        },
    ),
    (
        ClickUpApiKeyChecker,
        CLICKUP_KEY,
        "https://api.clickup.com/api/v2/user",
        {"Authorization": CLICKUP_KEY},
        {"user": {"id": 123, "username": "synthetic-user"}},
    ),
    (
        VercelAccessTokenChecker,
        VERCEL_TOKEN,
        "https://api.vercel.com/v2/user",
        {"Authorization": "Bearer" + " " + VERCEL_TOKEN},
        {"user": {"id": "synthetic-user-id"}, "limited": True},
    ),
    (
        VercelCliTokenChecker,
        VERCEL_TOKEN,
        "https://api.vercel.com/v2/user",
        {"Authorization": "Bearer" + " " + VERCEL_TOKEN},
        {"user": {"id": "synthetic-user-id"}, "limited": True},
    ),
    (
        DatadogApiKeyChecker,
        DATADOG_KEY,
        "https://api.datadoghq.com/api/v1/validate",
        {"DD-API-KEY": DATADOG_KEY},
        {"valid": True},
    ),
    (
        LaunchDarklyApiKeyChecker,
        LAUNCHDARKLY_KEY,
        "https://app.launchdarkly.com/api/v2/caller-identity",
        {"Authorization": LAUNCHDARKLY_KEY},
        {"accountId": "synthetic-account-id", "memberId": "synthetic-member-id"},
    ),
    (
        LaunchDarklyAccessTokenChecker,
        LAUNCHDARKLY_ALIAS_KEY,
        "https://app.launchdarkly.com/api/v2/caller-identity",
        {"Authorization": LAUNCHDARKLY_ALIAS_KEY},
        {
            "accountId": "synthetic-account-id",
            "serviceToken": True,
            "tokenId": "synthetic-token-id",
            "scopes": ["projects:read"],
        },
    ),
    (
        PagerDutyApiKeyChecker,
        PAGERDUTY_KEY,
        "https://api.pagerduty.com/abilities",
        {
            "Authorization": f"Token token={PAGERDUTY_KEY}",
            "Accept": "application/vnd.pagerduty+json;version=2",
        },
        {"abilities": ["users.read", "incidents.read"]},
    ),
    (
        BrowserStackTokenUrlChecker,
        BROWSERSTACK_SECRET,
        "https://api.browserstack.com/automate/plan.json",
        None,
        {
            "automate_plan": "Synthetic Automate",
            "parallel_sessions_running": 0,
            "parallel_sessions_max_allowed": 1,
        },
    ),
]


@pytest.mark.parametrize("checker_type,secret,url,headers,payload", CHECKS)
def test_success_request_contract(
    monkeypatch: pytest.MonkeyPatch,
    checker_type: type[Checker],
    secret: str,
    url: str,
    headers: dict[str, str] | None,
    payload: object,
) -> None:
    calls = mock_http(monkeypatch, FakeResponse(200, payload))

    assert checker_type(timeout=9).check(secret) is True

    assert len(calls) == 1
    session, method, request_url, kwargs = calls[0]
    assert method == ("POST" if checker_type is FlickrApiKeyChecker else "GET")
    assert request_url == url
    assert kwargs == {
        "headers": headers,
        "params": None,
        "data": (
            {
                "method": "flickr.test.echo",
                "api_key": FLICKR_KEY,
                "format": "json",
                "nojsoncallback": "1",
            }
            if checker_type is FlickrApiKeyChecker
            else None
        ),
        "auth": (
            (BROWSERSTACK_USER, BROWSERSTACK_KEY)
            if checker_type is BrowserStackTokenUrlChecker
            else None
        ),
        "timeout": 9,
        "allow_redirects": False,
    }
    assert session.trust_env is False
    assert session.cookies.get_dict() == {}


@pytest.mark.parametrize("checker_type,secret,url,headers,payload", CHECKS)
@pytest.mark.parametrize("status_code", [401, 403, 429, 500])
def test_ambiguous_statuses_are_unknown(
    monkeypatch: pytest.MonkeyPatch,
    checker_type: type[Checker],
    secret: str,
    url: str,
    headers: dict[str, str] | None,
    payload: object,
    status_code: int,
) -> None:
    mock_http(monkeypatch, FakeResponse(status_code, payload))
    assert checker_type().check(secret) is None


@pytest.mark.parametrize("checker_type,secret,url,headers,payload", CHECKS)
def test_invalid_json_and_request_errors_are_unknown(
    monkeypatch: pytest.MonkeyPatch,
    checker_type: type[Checker],
    secret: str,
    url: str,
    headers: dict[str, str] | None,
    payload: object,
) -> None:
    mock_http(monkeypatch, FakeResponse(200, ValueError("synthetic malformed body")))
    assert checker_type().check(secret) is None

    mock_http(monkeypatch, error=requests.Timeout("synthetic transport failure"))
    assert checker_type().check(secret) is None


@pytest.mark.parametrize(
    "payload,expected",
    [
        ({"stat": "fail", "code": 100}, False),
        ({"stat": "fail", "code": "100"}, False),
        ({"stat": "fail", "code": 99}, None),
        ({"stat": "fail", "code": "0100"}, None),
        ({"stat": "fail", "code": 100.0}, None),
        ({"stat": "fail"}, None),
        ({"stat": "ok", "code": 100}, True),
    ],
)
def test_flickr_only_exact_documented_error_code_is_invalid(
    monkeypatch: pytest.MonkeyPatch, payload: dict[str, object], expected: bool | None
) -> None:
    mock_http(monkeypatch, FakeResponse(200, payload))
    assert FlickrApiKeyChecker().check(FLICKR_KEY) is expected


def test_flickr_documented_error_code_on_ambiguous_status_is_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_http(monkeypatch, FakeResponse(403, {"stat": "fail", "code": "100"}))
    assert FlickrApiKeyChecker().check(FLICKR_KEY) is None


@pytest.mark.parametrize(
    "checker_type,secret,payload",
    [
        (ClickUpApiKeyChecker, CLICKUP_KEY, {"user": {}}),
        (ClickUpApiKeyChecker, CLICKUP_KEY, {"user": {"id": True}}),
        (ClickUpApiKeyChecker, CLICKUP_KEY, {"user": {"id": 0}}),
        (VercelAccessTokenChecker, VERCEL_TOKEN, {"user": {}}),
        (VercelAccessTokenChecker, VERCEL_TOKEN, {"user": {"id": ""}}),
        (VercelAccessTokenChecker, VERCEL_TOKEN, {"user": {"id": "  "}}),
        (VercelAccessTokenChecker, VERCEL_TOKEN, {"user": {"id": 123}}),
        (VercelCliTokenChecker, VERCEL_TOKEN, {"user": {"id": True}}),
        (VercelCliTokenChecker, VERCEL_TOKEN, {"user": {"id": "  "}}),
        (VercelCliTokenChecker, VERCEL_TOKEN, {"user": {"id": 123}}),
        (DatadogApiKeyChecker, DATADOG_KEY, {}),
        (DatadogApiKeyChecker, DATADOG_KEY, {"valid": False}),
        (DatadogApiKeyChecker, DATADOG_KEY, {"valid": 1}),
        (DatadogApiKeyChecker, DATADOG_KEY, {"valid": "true"}),
        (LaunchDarklyApiKeyChecker, LAUNCHDARKLY_KEY, {"accountId": ""}),
        (LaunchDarklyApiKeyChecker, LAUNCHDARKLY_KEY, {"accountId": 123}),
        (LaunchDarklyAccessTokenChecker, LAUNCHDARKLY_ALIAS_KEY, {"accountId": []}),
        (BrowserStackTokenUrlChecker, BROWSERSTACK_SECRET, {}),
        (BrowserStackTokenUrlChecker, BROWSERSTACK_SECRET, {"error": "denied"}),
        (BrowserStackTokenUrlChecker, BROWSERSTACK_SECRET, {"automate_plan": ""}),
        (BrowserStackTokenUrlChecker, BROWSERSTACK_SECRET, {"automate_plan": 1}),
        (PagerDutyApiKeyChecker, PAGERDUTY_KEY, {}),
        (PagerDutyApiKeyChecker, PAGERDUTY_KEY, {"abilities": "read"}),
        (PagerDutyApiKeyChecker, PAGERDUTY_KEY, {"abilities": ["read", 1]}),
    ],
)
def test_malformed_success_bodies_are_unknown(
    monkeypatch: pytest.MonkeyPatch,
    checker_type: type[Checker],
    secret: str,
    payload: object,
) -> None:
    mock_http(monkeypatch, FakeResponse(200, payload))
    assert checker_type().check(secret) is None


DATADOG_SITES = {
    "datadoghq.com": "api.datadoghq.com",
    "us3.datadoghq.com": "api.us3.datadoghq.com",
    "us5.datadoghq.com": "api.us5.datadoghq.com",
    "datadoghq.eu": "api.datadoghq.eu",
    "ap1.datadoghq.com": "api.ap1.datadoghq.com",
    "ap2.datadoghq.com": "api.ap2.datadoghq.com",
    "uk1.datadoghq.com": "api.uk1.datadoghq.com",
    "ddog-gov.com": "api.ddog-gov.com",
    "us2.ddog-gov.com": "api.us2.ddog-gov.com",
}


@pytest.mark.parametrize("site,host", DATADOG_SITES.items())
def test_datadog_sites(monkeypatch: pytest.MonkeyPatch, site: str, host: str) -> None:
    monkeypatch.setenv("DATADOG_SITE", site)
    calls = mock_http(monkeypatch, FakeResponse(200, {"valid": True}))
    assert DatadogApiKeyChecker().check(DATADOG_KEY) is True
    assert calls[0][2] == f"https://{host}/api/v1/validate"


@pytest.mark.parametrize(
    "checker_type,environment,expected_url",
    [
        (
            DatadogApiKeyChecker,
            "DATADOG_SITE",
            "https://api.datadoghq.com/api/v1/validate",
        ),
        (
            LaunchDarklyApiKeyChecker,
            "LAUNCHDARKLY_HOST",
            "https://app.launchdarkly.com/api/v2/caller-identity",
        ),
        (
            PagerDutyApiKeyChecker,
            "PAGERDUTY_HOST",
            "https://api.pagerduty.com/abilities",
        ),
    ],
)
def test_default_region_hosts(
    monkeypatch: pytest.MonkeyPatch,
    checker_type: type[Checker],
    environment: str,
    expected_url: str,
) -> None:
    monkeypatch.delenv(environment, raising=False)
    success = CHECKS[next(i for i, row in enumerate(CHECKS) if row[0] is checker_type)][4]
    calls = mock_http(monkeypatch, FakeResponse(200, success))
    secret = {
        DatadogApiKeyChecker: DATADOG_KEY,
        LaunchDarklyApiKeyChecker: LAUNCHDARKLY_KEY,
        PagerDutyApiKeyChecker: PAGERDUTY_KEY,
    }[checker_type]
    assert checker_type().check(secret) is True
    assert calls[0][2] == expected_url


@pytest.mark.parametrize(
    "checker_type,environment",
    [
        (DatadogApiKeyChecker, "DATADOG_SITE"),
        (LaunchDarklyApiKeyChecker, "LAUNCHDARKLY_HOST"),
        (LaunchDarklyAccessTokenChecker, "LAUNCHDARKLY_HOST"),
        (PagerDutyApiKeyChecker, "PAGERDUTY_HOST"),
    ],
)
def test_invalid_region_configuration_does_not_make_request(
    monkeypatch: pytest.MonkeyPatch, checker_type: type[Checker], environment: str
) -> None:
    monkeypatch.setenv(environment, "attacker.example")
    calls = mock_http(monkeypatch, FakeResponse(200, {}))
    secret = LAUNCHDARKLY_KEY if "LaunchDarkly" in checker_type.__name__ else "synthetic-token"
    assert checker_type().check(secret) is None
    assert calls == []


@pytest.mark.parametrize(
    "host",
    ["app.launchdarkly.com", "app.eu.launchdarkly.com", "app.launchdarkly.us"],
)
def test_launchdarkly_hosts(monkeypatch: pytest.MonkeyPatch, host: str) -> None:
    monkeypatch.setenv("LAUNCHDARKLY_HOST", host)
    calls = mock_http(monkeypatch, FakeResponse(200, {"accountId": "synthetic-account"}))
    assert LaunchDarklyApiKeyChecker().check(LAUNCHDARKLY_KEY) is True
    assert calls[0][2] == f"https://{host}/api/v2/caller-identity"


def test_launchdarkly_alias_inherits_host_and_accepts_service_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LAUNCHDARKLY_HOST", "app.eu.launchdarkly.com")
    payload = {
        "accountId": "synthetic-account",
        "serviceToken": True,
        "tokenId": "synthetic-token-id",
        "scopes": ["projects:read"],
    }
    calls = mock_http(monkeypatch, FakeResponse(200, payload))
    assert LaunchDarklyAccessTokenChecker().check(LAUNCHDARKLY_ALIAS_KEY) is True
    assert calls[0][2] == "https://app.eu.launchdarkly.com/api/v2/caller-identity"


@pytest.mark.parametrize(
    "secret",
    [
        "sdk-22222222-2222-2222-2222-222222222222",
        "mobile-22222222-2222-2222-2222-222222222222",
        "api-",
        "api- ",
        "api-token\n",
    ],
)
@pytest.mark.parametrize(
    "checker_type",
    [LaunchDarklyApiKeyChecker, LaunchDarklyAccessTokenChecker],
)
def test_launchdarkly_unsupported_token_classes_do_not_make_request(
    monkeypatch: pytest.MonkeyPatch, checker_type: type[Checker], secret: str
) -> None:
    calls = mock_http(monkeypatch, FakeResponse(200, {"accountId": "synthetic-account"}))
    assert checker_type().check(secret) is None
    assert calls == []


@pytest.mark.parametrize(
    "secret",
    [
        "missing-colon",
        ":key",
        "user:",
        "user%3Aname:key",
        "user:bad%encoding",
        "user:%FF",
        "user:%0Akey",
        "user:%20%20",
        "\ud800:key",
    ],
)
def test_malformed_browserstack_credentials_do_not_make_request(
    monkeypatch: pytest.MonkeyPatch, secret: str
) -> None:
    calls = mock_http(monkeypatch, FakeResponse(200, {}))
    assert BrowserStackTokenUrlChecker().check(secret) is None
    assert calls == []


@pytest.mark.parametrize(
    "secret",
    ["", " ", "synthetic-key\n", "synthetic-key\t", "synthetic-kéy", "\ud800"],
)
def test_invalid_flickr_input_does_not_make_request(
    monkeypatch: pytest.MonkeyPatch, secret: str
) -> None:
    calls = mock_http(monkeypatch, FakeResponse(200, {"stat": "ok"}))
    assert FlickrApiKeyChecker().check(secret) is None
    assert calls == []


PINNED_PATTERN_SOURCE = (
    "https://github.com/advanced-security/secret-scanning-custom-patterns/blob/"
    "01dbee8dc02f9f1ab0cfe54c86115b75b22908a6/vendors/patterns.yml"
)

# Bodies and selected surrounding captures are copied from the pinned YAML.
# These fixtures check formats and boundaries only, not GitHub/Hyperscan scanning.
PATTERN_EXAMPLES = [
    (
        "flickr_api_key",
        r"[0-9a-f]{32}",
        "https://api.flickr.com/services/rest/?method=flickr.test.echo&api_key="
        + FLICKR_KEY
        + "&format=json",
        "https://api.flickr.com/services/rest/?method=flickr.test.echo&api_key=",
        FLICKR_KEY,
        "&format=json",
    ),
    (
        "clickup_api_key",
        r"pk_[0-9]{6,8}_[A-Z0-9]{32}",
        f'CLICKUP_API_KEY: "{CLICKUP_KEY}"',
        'CLICKUP_API_KEY: "',
        CLICKUP_KEY,
        '"',
    ),
    (
        "vercel_access_token",
        r"[A-Za-z0-9]{24}",
        f"VERCEL_ACCESS_TOKEN={VERCEL_TOKEN}\n",
        "VERCEL_ACCESS_TOKEN=",
        VERCEL_TOKEN,
        "\n",
    ),
    (
        "vercel_cli_token",
        r"[A-Za-z0-9]{24}",
        f"vercel deploy --token={VERCEL_TOKEN}\n",
        "vercel deploy --token=",
        VERCEL_TOKEN,
        "\n",
    ),
    (
        "datadog_api_key",
        r"[a-f0-9]{32}",
        f"DD_API_KEY={DATADOG_KEY}\n",
        "DD_API_KEY=",
        DATADOG_KEY,
        "\n",
    ),
    (
        "launchdarkly_api_key",
        r"(api|sdk)-[a-f0-9-]{8}-[a-f0-9-]{4}-[a-f0-9-]{4}-[a-f0-9-]{4}-[a-f0-9-]{12}",
        f"const key = {LAUNCHDARKLY_KEY};",
        "const key = ",
        LAUNCHDARKLY_KEY,
        ";",
    ),
    (
        "launchdarkly_access_token",
        r"(api|sdk)-[a-f0-9-]{8}-[a-f0-9-]{4}-[a-f0-9-]{4}-[a-f0-9-]{4}-[a-f0-9-]{12}",
        f"const token = {LAUNCHDARKLY_ALIAS_KEY};",
        "const token = ",
        LAUNCHDARKLY_ALIAS_KEY,
        ";",
    ),
    (
        "pagerduty_api_key",
        r"[A-Za-z0-9_-]{20}",
        f"pd_api_key={PAGERDUTY_KEY}\n",
        "pd_api_key=",
        PAGERDUTY_KEY,
        "\n",
    ),
    (
        "browserstack_token_url",
        r"[^:]+:[0-9a-zA-Z]{20}",
        f"https://{BROWSERSTACK_SECRET}@hub-cloud.browserstack.com/wd/hub",
        "https://",
        BROWSERSTACK_SECRET,
        "@hub-cloud.browserstack.com/wd/hub",
    ),
]


@pytest.mark.parametrize(
    "secret_type,pattern,snippet,prefix,capture,suffix",
    PATTERN_EXAMPLES,
)
def test_examples_match_pinned_pattern_bodies_and_capture_boundaries(
    secret_type: str, pattern: str, snippet: str, prefix: str, capture: str, suffix: str
) -> None:
    assert PINNED_PATTERN_SOURCE.endswith("/vendors/patterns.yml")
    assert secret_type in {row[0].name for row in CHECKS}
    assert snippet == prefix + capture + suffix
    match = re.fullmatch(re.escape(prefix) + f"({pattern})" + re.escape(suffix), snippet)
    assert match is not None
    assert match.group(1) == capture


def test_datadog_example_avoids_pinned_exclusions() -> None:
    exclusions = [
        r"^0+$",
        r"^1+$",
        r"^ef8d5de700e7989468166c40fc8a0ccd$",
        r"^(a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5|1234567890abcdef1234567890abcdef)$",
    ]
    assert not any(re.fullmatch(pattern, DATADOG_KEY) for pattern in exclusions)


def test_prepared_auth_headers_and_environment_isolation(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    cases = [
        (ClickUpApiKeyChecker(), CLICKUP_KEY, "Authorization", CLICKUP_KEY),
        (
            VercelAccessTokenChecker(),
            VERCEL_TOKEN,
            "Authorization",
            "Bearer" + " " + VERCEL_TOKEN,
        ),
        (
            VercelCliTokenChecker(),
            VERCEL_TOKEN,
            "Authorization",
            "Bearer" + " " + VERCEL_TOKEN,
        ),
        (
            BrowserStackTokenUrlChecker(),
            BROWSERSTACK_SECRET,
            "Authorization",
            "Basic "
            + base64.b64encode(f"{BROWSERSTACK_USER}:{BROWSERSTACK_KEY}".encode()).decode(),
        ),
    ]
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:8080")
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.invalid:8080")
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", "/nonexistent/custom-ca.pem")
    caplog.set_level(logging.DEBUG)

    def unexpected_netrc(*args: object, **kwargs: object) -> None:
        raise AssertionError("ambient netrc must not be read")

    monkeypatch.setattr(requests.sessions, "get_netrc_auth", unexpected_netrc)

    for checker, secret, header_name, header_value in cases:
        response_body = (
            {"user": {"id": "synthetic-id"}, "limited": True}
            if isinstance(checker, VercelAccessTokenChecker)
            else (
                {"automate_plan": "Synthetic Automate"}
                if isinstance(checker, BrowserStackTokenUrlChecker)
                else {"user": {"id": 123}}
            )
        )
        prepared = install_adapter(monkeypatch, payload=response_body)
        assert checker.check(secret) is True
        request, settings = prepared[0]
        assert request.headers[header_name] == header_value
        assert "Cookie" not in request.headers
        assert settings["proxies"] == {}
        assert settings["verify"] is True
        assert secret not in caplog.text
        assert header_value not in caplog.text


@pytest.mark.parametrize(
    "secret,expected",
    [
        (
            BROWSERSTACK_SECRET,
            "Basic "
            + base64.b64encode(f"{BROWSERSTACK_USER}:{BROWSERSTACK_KEY}".encode()).decode(),
        ),
        (
            "synthetic%40example.com:key%2Fpart",
            "Basic " + base64.b64encode(b"synthetic@example.com:key/part").decode(),
        ),
    ],
)
def test_browserstack_basic_auth_uses_decoded_username_and_key(
    monkeypatch: pytest.MonkeyPatch, secret: str, expected: str
) -> None:
    prepared = install_adapter(monkeypatch, payload={"automate_plan": "Synthetic Automate"})
    assert BrowserStackTokenUrlChecker().check(secret) is True
    assert prepared[0][0].headers["Authorization"] == expected


def test_browserstack_parser_keeps_extra_colons_in_access_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = mock_http(monkeypatch, FakeResponse(200, {"automate_plan": "Synthetic Automate"}))
    parsed_secret = f"{BROWSERSTACK_USER}:{BROWSERSTACK_KEY}:extra"
    assert BrowserStackTokenUrlChecker().check(parsed_secret) is True
    assert calls[0][3]["auth"] == (BROWSERSTACK_USER, f"{BROWSERSTACK_KEY}:extra")


@pytest.mark.parametrize(
    "error",
    [requests.ConnectionError("synthetic disconnect"), SSLError("synthetic TLS")],
)
def test_adapter_connection_failures_are_unknown_and_redacted(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    error: requests.RequestException,
) -> None:
    caplog.set_level(logging.DEBUG)
    install_adapter(monkeypatch, error=error)
    assert ClickUpApiKeyChecker().check(CLICKUP_KEY) is None
    assert CLICKUP_KEY not in caplog.text
    assert str(error) not in caplog.text


@pytest.mark.parametrize("status_code", [301, 302, 303, 307, 308])
def test_redirect_is_not_followed(monkeypatch: pytest.MonkeyPatch, status_code: int) -> None:
    prepared = install_adapter(
        monkeypatch,
        status_code=status_code,
        headers={"Location": "https://attacker.example/redirected"},
        payload={"user": {"id": 123}},
    )
    assert ClickUpApiKeyChecker().check(CLICKUP_KEY) is None
    assert len(prepared) == 1


def test_prepared_transport_errors_and_malformed_json_do_not_log_credentials(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    install_adapter(
        monkeypatch,
        body=b'{"detail":"' + BROWSERSTACK_SECRET.encode() + b'","invalid":',
    )
    assert BrowserStackTokenUrlChecker().check(BROWSERSTACK_SECRET) is None
    assert BROWSERSTACK_SECRET not in caplog.text
    basic = base64.b64encode(f"{BROWSERSTACK_USER}:{BROWSERSTACK_KEY}".encode()).decode()
    assert basic not in caplog.text


def test_flickr_post_keeps_echoed_key_out_of_debug_logs(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    received: dict[str, str] = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers["Content-Length"])
            received["path"] = self.path
            received["body"] = self.rfile.read(length).decode("ascii")
            body = json.dumps({"stat": "ok", "api_key": FLICKR_KEY}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            return

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    previous_level = logging.getLogger().level
    monkeypatch.setattr(
        FlickrApiKeyChecker,
        "URL",
        f"http://127.0.0.1:{server.server_port}/services/rest/",
    )
    caplog.set_level(logging.DEBUG, logger="urllib3.connectionpool")
    thread.start()
    try:
        assert FlickrApiKeyChecker(debug=True).check(FLICKR_KEY) is True
    finally:
        server.shutdown()
        thread.join()
        server.server_close()
        logging.getLogger().setLevel(previous_level)

    assert received["path"] == "/services/rest/"
    assert parse_qs(received["body"]) == {
        "method": ["flickr.test.echo"],
        "api_key": [FLICKR_KEY],
        "format": ["json"],
        "nojsoncallback": ["1"],
    }
    assert FLICKR_KEY not in caplog.text


def test_transport_does_not_log_success_secrets(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    install_adapter(monkeypatch, payload={"user": {"id": 123}})
    assert ClickUpApiKeyChecker().check(CLICKUP_KEY) is True
    assert CLICKUP_KEY not in caplog.text


def test_basic_auth_transport_failure_does_not_log_credentials(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    basic = base64.b64encode(f"{BROWSERSTACK_USER}:{BROWSERSTACK_KEY}".encode()).decode()
    caplog.set_level(logging.DEBUG)
    install_adapter(
        monkeypatch,
        error=requests.ConnectionError(f"synthetic error {BROWSERSTACK_SECRET} Basic {basic}"),
    )
    assert BrowserStackTokenUrlChecker().check(BROWSERSTACK_SECRET) is None
    assert BROWSERSTACK_SECRET not in caplog.text
    assert BROWSERSTACK_KEY not in caplog.text
    assert basic not in caplog.text
