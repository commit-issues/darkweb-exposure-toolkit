#!/usr/bin/env python3
"""
Check emails, usernames, and passwords against HaveIBeenPwned API.

Privacy model:
- Emails and usernames are sent to the HIBP API — same exposure
  as using haveibeenpwned.com directly in your browser.
- Passwords use k-anonymity: only a 5-char SHA-1 prefix is sent.
  Your full password never leaves your machine.
- Phone numbers are checked via HIBP breach search.
"""

import hashlib
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


HIBP_BASE = "https://haveibeenpwned.com/api/v3"
PWNED_BASE = "https://api.pwnedpasswords.com"
HEADERS: Dict[str, str] = {
    "User-Agent": "darkweb-exposure-toolkit/2.0 (personal-security-scanner)",
}

API_KEY = os.getenv("HIBP_API_KEY", "")
if API_KEY:
    HEADERS["hibp-api-key"] = API_KEY


def _get(url: str, params: Optional[Dict] = None) -> Optional[requests.Response]:
    """Shared GET with timeout and basic error handling."""
    try:
        response = requests.get(url, headers=HEADERS, params=params, timeout=20)
        time.sleep(1.5)
        return response
    except requests.exceptions.ConnectionError:
        print("  No internet connection — check skipped.")
        return None
    except requests.exceptions.Timeout:
        print("  Request timed out — check skipped.")
        return None
    except requests.exceptions.RequestException as exc:
        print(f"  Request error: {exc}")
        return None


def check_email(email: str) -> Optional[List[Dict]]:
    """
    Check if an email appears in known data breaches.

    Returns list of breach dicts, empty list if clean, None on error.
    """
    url = f"{HIBP_BASE}/breachedaccount/{email}"
    response = _get(url, params={"truncateResponse": "false"})
    if response is None:
        return None
    if response.status_code == 200:
        return response.json()  # type: ignore[no-any-return]
    if response.status_code == 404:
        return []
    if response.status_code == 401:
        print("  HIBP API key missing or invalid.")
        return None
    if response.status_code == 429:
        print("  Rate limit hit — wait 1-2 minutes and retry.")
        return None
    print(f"  HIBP returned HTTP {response.status_code}")
    return None


def check_password(password: str) -> int:
    """
    Check if a password appears in breach dumps using k-anonymity.

    Only the first 5 chars of the SHA-1 hash are transmitted.
    Your full password never leaves your machine.

    Returns count of times seen (0 = not found, -1 = error).
    """
    sha1 = (
        hashlib.sha1(password.encode("utf-8"), usedforsecurity=False)
        .hexdigest()
        .upper()
    )
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        response = requests.get(
            f"{PWNED_BASE}/range/{prefix}",
            timeout=10,
        )
        response.raise_for_status()
        for line in response.text.splitlines():
            parts = line.split(":")
            if len(parts) == 2 and parts[0] == suffix:
                return int(parts[1])
        return 0
    except requests.exceptions.RequestException as exc:
        print(f"  Password check error: {exc}")
        return -1


def check_username(username: str) -> Optional[List[Dict]]:
    """
    Check if a username appears in known data breaches.

    Returns list of breach dicts, empty list if clean, None on error.
    """
    url = f"{HIBP_BASE}/breachedaccount/{username}"
    response = _get(url, params={"truncateResponse": "false"})
    if response is None:
        return None
    if response.status_code == 200:
        return response.json()  # type: ignore[no-any-return]
    if response.status_code == 404:
        return []
    print(f"  HIBP returned HTTP {response.status_code}")
    return None


def check_phone(phone: str) -> Optional[List[Dict]]:
    """
    Check if a phone number appears in known data breaches.

    Args:
        phone: Phone number with country code e.g. +11234567890

    Returns list of breach dicts, empty list if clean, None on error.
    """
    url = f"{HIBP_BASE}/breachedaccount/{phone}"
    response = _get(url, params={"truncateResponse": "false"})
    if response is None:
        return None
    if response.status_code == 200:
        return response.json()  # type: ignore[no-any-return]
    if response.status_code == 404:
        return []
    print(f"  HIBP returned HTTP {response.status_code}")
    return None
