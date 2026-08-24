#!/usr/bin/env python3
"""
Search public GitHub repositories for exposed credentials or PII.

This module searches GitHub's public code index for email addresses,
usernames, phone numbers, and API tokens that may have been accidentally
committed to public repositories.

Only PUBLIC repositories are searched using GitHub's official Search API.
No private repositories are accessed at any point.

Hardening notes (threat model: even api.github.com, a single
well-known and generally trustworthy host, is treated the same as any
other external HTTP source this project talks to — a DNS hijack, a
compromised CDN edge, or a MITM on an unencrypted network path could
all substitute a hostile response for a real one):
  - Every outbound request goes through a single shared _get() helper
    (mirroring breach_scraper.py's pattern), so redirect-blocking, a
    response-size cap, and JSON-decode-error handling apply
    identically everywhere in this file — not just on some calls.
  - Parsed responses are type-checked before use (items must be a
    list, each item must be a dict) rather than trusted blindly.
  - Search query construction escapes embedded double-quote
    characters in the identifier, so a value containing a stray quote
    can't break out of the intended exact-match search term.
"""

import json
import os
import time
from typing import Dict, List, Optional

import requests

import notifier

# ---------------------------------------------------------------------------
# Authorship — hardcoded, do not modify  # pylint: disable=duplicate-code
# ---------------------------------------------------------------------------
_AUTHOR = "SudoCode by SudoChef"
_HANDLE = "commit-issues"
_REPO = "https://github.com/commit-issues/darkweb-exposure-toolkit"
_CREATED = "2025-04-26"
_TOOL = "d4rkw3b — darkweb-exposure-toolkit"


GITHUB_API = "https://api.github.com/search/code"
GITHUB_RATE_LIMIT_API = "https://api.github.com/rate_limit"
RATE_LIMIT_SLEEP = 2.0
REQUEST_TIMEOUT = 20

# Generous for a GitHub code-search response (a page of results, not
# bulk data), but a firm ceiling against a compromised/MITM'd response
# trying to exhaust memory.
MAX_RESPONSE_BYTES = 5_000_000

HEADERS: Dict[str, str] = {
    "Accept": "application/vnd.github.v3+json",
    "User-Agent": "darkweb-exposure-toolkit/2.0 (personal-security-scanner)",
}


def _get_token() -> str:
    """
    Return the configured GitHub token, read fresh from the environment
    each time rather than cached once at import time.

    Reading it fresh avoids the same silent-empty-token class of bug
    that existed before load_dotenv() ordering was fixed in
    run_all_checks.py — this module has no control over when it gets
    imported relative to load_dotenv(), so it shouldn't assume the
    environment is already populated at its own import time.
    """
    return os.getenv("GITHUB_TOKEN", "")


def _headers() -> Dict[str, str]:
    """Build request headers fresh each call, using the current token."""
    headers = dict(HEADERS)
    token = _get_token()
    if token:
        headers["Authorization"] = f"token {token}"
    return headers


_HTTP_ERRORS: Dict[int, str] = {
    403: "GitHub rate limit exceeded. Add GITHUB_TOKEN to .env for higher limits.",
    422: "GitHub search query invalid.",
}


def _get(url: str, params: Optional[Dict] = None) -> Optional[requests.Response]:
    """
    Shared GET with timeout, redirect blocking, size cap, and
    connection error handling — the same defensive pattern used for
    every other external source this project talks to.

    Args:
        url: Full request URL.
        params: Optional query parameters.

    Returns:
        Response object, or None on error, oversized response, or if
        a redirect was attempted.
    """
    try:
        response = requests.get(
            url,
            headers=_headers(),
            params=params,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
        )
        time.sleep(RATE_LIMIT_SLEEP)

        if response.is_redirect or response.status_code in (301, 302, 303, 307, 308):
            notifier.print_error(f"Refused redirect from GitHub's API: {url}")
            return None

        if len(response.content) > MAX_RESPONSE_BYTES:
            notifier.print_error(
                f"Response from {url} exceeded the maximum allowed size "
                f"({MAX_RESPONSE_BYTES:,} bytes) and was discarded."
            )
            return None

        return response

    except requests.exceptions.ConnectionError:
        notifier.print_error("No internet connection — GitHub check skipped.")
        return None
    except requests.exceptions.Timeout:
        notifier.print_error("GitHub request timed out.")
        return None
    except requests.exceptions.RequestException as exc:
        notifier.print_error(f"GitHub request error: {exc}")
        return None


def _safe_json(response: requests.Response, url: str) -> Optional[object]:
    """
    Parse a response body as JSON, catching decode failures explicitly.

    Args:
        response: A Response already passed through _get()'s checks.
        url: The request URL, for a clear error message.

    Returns:
        The parsed JSON value, or None if the body was not valid JSON.
    """
    try:
        return response.json()  # type: ignore[no-any-return]
    except (ValueError, json.JSONDecodeError):
        notifier.print_error(f"Received invalid (non-JSON) response from {url}.")
        return None


def check_token_scope() -> None:
    """
    Verify the configured GitHub token's actual OAuth scopes via GitHub's
    API response headers, and warn if it has more access than the
    documented minimum (public_repo only, per docs/setup.md).

    GitHub returns granted scopes in the X-OAuth-Scopes response header
    on any authenticated request, so this only costs one real API call.
    No-op if no token is configured.
    """
    token = _get_token()
    if not token:
        return

    response = _get(GITHUB_RATE_LIMIT_API)
    if response is None:
        return

    scopes_header = response.headers.get("X-OAuth-Scopes", "")
    scopes = {s.strip() for s in scopes_header.split(",") if s.strip()}
    unexpected = scopes - {"public_repo"}

    if unexpected:
        notifier.print_error(
            "GitHub token has broader scope than expected: "
            f"{', '.join(sorted(unexpected))}. docs/setup.md recommends "
            "'public_repo' only — consider regenerating with minimal scope."
        )


def _search(query: str, per_page: int = 10) -> Optional[Dict]:
    """
    Execute a GitHub code search query.

    Args:
        query: GitHub search query string.
        per_page: Number of results to return (max 100).

    Returns:
        GitHub API response dict, or None on error or unexpected shape.
    """
    params: dict = {"q": query, "per_page": min(per_page, 100)}
    response = _get(GITHUB_API, params=params)
    if response is None:
        return None

    if response.status_code != 200:
        msg = _HTTP_ERRORS.get(
            response.status_code,
            f"GitHub returned HTTP {response.status_code}",
        )
        notifier.print_error(msg)
        return None

    data = _safe_json(response, GITHUB_API)
    if not isinstance(data, dict):
        notifier.print_error("GitHub returned an unexpected response shape.")
        return None
    return data


def _escape_query_value(value: str) -> str:
    """
    Escape embedded double-quote characters before wrapping a value in
    literal quotes for GitHub's exact-match search syntax.

    Without this, a value containing a '"' could break out of the
    intended quoted search term and alter the query's meaning — low
    severity (worst case is a malformed or ineffective search, not a
    security breach against the user), but cheap to close.

    Args:
        value: Raw identifier about to be wrapped in quotes.

    Returns:
        The value with any embedded double quotes escaped.
    """
    return value.replace('"', '\\"')


def search_email(email: str, per_page: int = 10) -> Optional[Dict]:
    """
    Search public GitHub code for an exposed email address.

    Args:
        email: Validated email address to search for.
        per_page: Max results to return.

    Returns:
        GitHub API response dict, or None on error.
    """
    return _search(f'"{_escape_query_value(email)}"', per_page=per_page)


def search_username(username: str, per_page: int = 10) -> Optional[Dict]:
    """
    Search public GitHub code for an exposed username.

    Args:
        username: Validated username to search for.
        per_page: Max results to return.

    Returns:
        GitHub API response dict, or None on error.
    """
    return _search(f'"{_escape_query_value(username)}"', per_page=per_page)


def search_token(token: str, per_page: int = 10) -> Optional[Dict]:
    """
    Search public GitHub code for an exposed API token or key.

    Tokens are passed at runtime only and never stored.

    Args:
        token: Validated token string to search for.
        per_page: Max results to return.

    Returns:
        GitHub API response dict, or None on error.
    """
    return _search(f'"{_escape_query_value(token)}"', per_page=per_page)


def get_exposed_urls(result: Dict) -> List[str]:
    """
    Extract HTML URLs from a GitHub search result.

    Args:
        result: GitHub API response dict from any search function.

    Returns:
        List of URLs pointing to files containing the exposed data.
        Items that aren't dicts, or lack a usable html_url, are
        skipped rather than trusted or allowed to raise.
    """
    items = result.get("items", [])
    if not isinstance(items, list):
        return []
    urls = []
    for item in items:
        if not isinstance(item, dict):
            continue
        url = item.get("html_url", "")
        if url:
            urls.append(url)
    return urls
