#!/usr/bin/env python3
"""
Search public GitHub repositories for exposed credentials or PII.

This module searches GitHub's public code index for email addresses,
usernames, phone numbers, and API tokens that may have been accidentally
committed to public repositories.

Only PUBLIC repositories are searched using GitHub's official Search API.
No private repositories are accessed at any point.
"""

import os
import time
from typing import Dict, List, Optional

import requests

# ---------------------------------------------------------------------------
# Authorship — hardcoded, do not modify  # pylint: disable=duplicate-code
# ---------------------------------------------------------------------------
_AUTHOR = "SudoCode by SudoChef"
_HANDLE = "commit-issues"
_REPO = "https://github.com/commit-issues/darkweb-exposure-toolkit"
_CREATED = "2025-04-26"
_TOOL = "d4rkw3b — darkweb-exposure-toolkit"


GITHUB_API = "https://api.github.com/search/code"
RATE_LIMIT_SLEEP = 2.0

HEADERS: Dict[str, str] = {
    "Accept": "application/vnd.github.v3+json",
    "User-Agent": "darkweb-exposure-toolkit/2.0 (personal-security-scanner)",
}

TOKEN = os.getenv("GITHUB_TOKEN", "")
if TOKEN:
    HEADERS["Authorization"] = f"token {TOKEN}"

_HTTP_ERRORS: Dict[int, str] = {
    403: ("GitHub rate limit exceeded. " "Add GITHUB_TOKEN to .env for higher limits."),
    422: "GitHub search query invalid.",
}


def _search(query: str, per_page: int = 10) -> Optional[Dict]:
    """
    Execute a GitHub code search query.

    Args:
        query: GitHub search query string.
        per_page: Number of results to return (max 100).

    Returns:
        GitHub API response dict, or None on error.
    """
    params: dict[str, str | int] = {"q": query, "per_page": min(per_page, 100)}
    try:
        response = requests.get(GITHUB_API, headers=HEADERS, params=params, timeout=20)
        time.sleep(RATE_LIMIT_SLEEP)

        if response.status_code == 200:
            return response.json()  # type: ignore[no-any-return]

        msg = _HTTP_ERRORS.get(
            response.status_code,
            f"GitHub returned HTTP {response.status_code}",
        )
        print(f"  {msg}")
        return None

    except requests.exceptions.ConnectionError:
        print("  No internet connection — GitHub check skipped.")
        return None
    except requests.exceptions.Timeout:
        print("  GitHub request timed out.")
        return None
    except requests.exceptions.RequestException as exc:
        print(f"  GitHub request error: {exc}")
        return None


def search_email(email: str, per_page: int = 10) -> Optional[Dict]:
    """
    Search public GitHub code for an exposed email address.

    Args:
        email: Validated email address to search for.
        per_page: Max results to return.

    Returns:
        GitHub API response dict, or None on error.
    """
    return _search(f'"{email}"', per_page=per_page)


def search_username(username: str, per_page: int = 10) -> Optional[Dict]:
    """
    Search public GitHub code for an exposed username.

    Args:
        username: Validated username to search for.
        per_page: Max results to return.

    Returns:
        GitHub API response dict, or None on error.
    """
    return _search(f'"{username}"', per_page=per_page)


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
    return _search(f'"{token}"', per_page=per_page)


def get_exposed_urls(result: Dict) -> List[str]:
    """
    Extract HTML URLs from a GitHub search result.

    Args:
        result: GitHub API response dict from any search function.

    Returns:
        List of URLs pointing to files containing the exposed data.
    """
    items = result.get("items", [])
    return [item.get("html_url", "") for item in items if item.get("html_url")]
