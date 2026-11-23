"""Vercel CLI token validator."""

from .vercel_access_token import VercelAccessTokenChecker


class VercelCliTokenChecker(VercelAccessTokenChecker):
    """Validate Vercel CLI tokens using the access-token endpoint."""

    name = "vercel_cli_token"
    description = "Validates Vercel CLI Tokens"
