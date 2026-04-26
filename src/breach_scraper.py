#!/usr/bin/env python3
"""
Multi-source breach intelligence scraper.

Polls multiple free public breach APIs and paste sites,
deduplicates results, and stores them in the local breach_cache table.

Sources (all free tier):
    HIBP         — HaveIBeenPwned API (free key required)
    LEAKCHECK    — LeakCheck.io free tier
    BREACHDIR    — BreachDirectory free API
    EMAILREP     — Emailrep.io free key
    OSINTLEAK    — OSINTLeak free starter
    PASTE        — psbdmp.ws paste site search

All results stored locally. Nothing shared externally.
Run manually or via scheduler.py for 24hr auto-refresh.

"""

import os
import time
from typing import Dict, List, Optional

import requests

from db_utils import BreachRecord, cache_breach

# ---------------------------------------------------------------------------
# Authorship — hardcoded, do not modify  # pylint: disable=duplicate-code
# ---------------------------------------------------------------------------
_AUTHOR = "SudoCode by SudoChef"
_HANDLE = "commit-issues"
_REPO = "https://github.com/commit-issues/darkweb-exposure-toolkit"
_CREATED = "2025-04-26"
_TOOL = "d4rkw3b — darkweb-exposure-toolkit"


RATE_LIMIT_SLEEP = 1.5
REQUEST_TIMEOUT = 20

HIBP_BASE = "https://haveibeenpwned.com/api/v3"
LEAKCHECK_BASE = "https://leakcheck.io/api/public"
BREACHDIR_BASE = "https://breachdirectory.org/api"
EMAILREP_BASE = "https://emailrep.io"
OSINTLEAK_BASE = "https://api.osintleak.com/v1"
PASTE_BASE = "https://psbdmp.ws/api/search"

_HEADERS: Dict[str, str] = {
    "User-Agent": "darkweb-exposure-toolkit/2.0 (personal-security-scanner)",
}

_HIBP_KEY = os.getenv("HIBP_API_KEY", "")
_EMAILREP_KEY = os.getenv("EMAILREP_API_KEY", "")
_OSINTLEAK_KEY = os.getenv("OSINTLEAK_API_KEY", "")

_HIBP_HEADERS = {**_HEADERS, "hibp-api-key": _HIBP_KEY} if _HIBP_KEY else _HEADERS
_EMAILREP_HEADERS = {**_HEADERS, "Key": _EMAILREP_KEY} if _EMAILREP_KEY else _HEADERS
_OSINTLEAK_HEADERS = (
    {**_HEADERS, "Authorization": f"Bearer {_OSINTLEAK_KEY}"}
    if _OSINTLEAK_KEY
    else _HEADERS
)


def _get(
    url: str,
    headers: Optional[Dict] = None,
    params: Optional[Dict] = None,
) -> Optional[requests.Response]:
    """
    Shared GET with timeout and connection error handling.

    Args:
        url: Full request URL.
        headers: Optional request headers.
        params: Optional query parameters.

    Returns:
        Response object or None on error.
    """
    try:
        response = requests.get(
            url,
            headers=headers or _HEADERS,
            params=params,
            timeout=REQUEST_TIMEOUT,
        )
        time.sleep(RATE_LIMIT_SLEEP)
        return response
    except requests.exceptions.ConnectionError:
        print(f"  Connection error: {url}")
        return None
    except requests.exceptions.Timeout:
        print(f"  Timeout: {url}")
        return None
    except requests.exceptions.RequestException as exc:
        print(f"  Request error: {exc}")
        return None


def _scrape_hibp(identifier: str) -> List[BreachRecord]:
    """
    Scrape HIBP breach data for an email or username.

    Requires HIBP_API_KEY in .env. Skipped silently if not set.

    Args:
        identifier: Email or username to search.

    Returns:
        List of BreachRecord objects from HIBP.
    """
    if not _HIBP_KEY:
        return []

    url = f"{HIBP_BASE}/breachedaccount/{identifier}"
    response = _get(
        url,
        headers=_HIBP_HEADERS,
        params={"truncateResponse": "false"},
    )
    if response is None or response.status_code != 200:
        return []

    records = []
    for breach in response.json():
        records.append(
            BreachRecord(
                identifier=identifier,
                source="HIBP",
                breach_name=breach.get("Name", "Unknown"),
                data_classes=", ".join(breach.get("DataClasses", [])),
                breach_date=breach.get("BreachDate", "Unknown"),
                raw_json=str(breach),
            )
        )
    return records


def _scrape_leakcheck(identifier: str) -> List[BreachRecord]:
    """
    Scrape LeakCheck free tier for an email or username.

    No API key required for free tier.

    Args:
        identifier: Email or username to search.

    Returns:
        List of BreachRecord objects from LeakCheck.
    """
    response = _get(LEAKCHECK_BASE, params={"check": identifier})
    if response is None or response.status_code != 200:
        return []

    data = response.json()
    if not data.get("success") or not data.get("sources"):
        return []

    records = []
    for source in data["sources"]:
        records.append(
            BreachRecord(
                identifier=identifier,
                source="LEAKCHECK",
                breach_name=source.get("name", "Unknown"),
                data_classes=source.get("fields", "Unknown"),
                breach_date=source.get("date", "Unknown"),
            )
        )
    return records


def _scrape_breachdirectory(identifier: str) -> List[BreachRecord]:
    """
    Scrape BreachDirectory free API for an email or username.

    No API key required.

    Args:
        identifier: Email or username to search.

    Returns:
        List of BreachRecord objects from BreachDirectory.
    """
    response = _get(
        f"{BREACHDIR_BASE}/search",
        params={"func": "auto", "term": identifier},
    )
    if response is None or response.status_code != 200:
        return []

    data = response.json()
    results = data.get("result", [])
    if not results:
        return []

    records = []
    for item in results[:10]:
        records.append(
            BreachRecord(
                identifier=identifier,
                source="BREACHDIR",
                breach_name=item.get("sources", ["Unknown"])[0],
                data_classes=", ".join(item.get("fields", [])),
                breach_date="Unknown",
                raw_json=str(item),
            )
        )
    return records


def _scrape_emailrep(identifier: str) -> List[BreachRecord]:
    """
    Scrape Emailrep.io for email reputation and breach history.

    Requires EMAILREP_API_KEY in .env for higher rate limits.
    Works without a key at reduced rate.

    Args:
        identifier: Email address to search.

    Returns:
        List of BreachRecord objects from Emailrep.
    """
    if "@" not in identifier:
        return []

    response = _get(
        f"{EMAILREP_BASE}/{identifier}",
        headers=_EMAILREP_HEADERS,
    )
    if response is None or response.status_code != 200:
        return []

    data = response.json()
    if not data.get("details", {}).get("data_breach"):
        return []

    return [
        BreachRecord(
            identifier=identifier,
            source="EMAILREP",
            breach_name="Data breach confirmed",
            data_classes=(
                f"Last breach: {data['details'].get('last_seen', 'Unknown')}"
            ),
            breach_date=data["details"].get("first_seen", "Unknown"),
            raw_json=str(data),
        )
    ]


def _scrape_osintleak(identifier: str) -> List[BreachRecord]:
    """
    Scrape OSINTLeak free starter for stealer logs and dark web data.

    Requires OSINTLEAK_API_KEY in .env. Skipped silently if not set.

    Args:
        identifier: Email or username to search.

    Returns:
        List of BreachRecord objects from OSINTLeak.
    """
    if not _OSINTLEAK_KEY:
        return []

    response = _get(
        f"{OSINTLEAK_BASE}/search",
        headers=_OSINTLEAK_HEADERS,
        params={"query": identifier},
    )
    if response is None or response.status_code != 200:
        return []

    data = response.json()
    results = data.get("results", [])

    records = []
    for item in results[:10]:
        records.append(
            BreachRecord(
                identifier=identifier,
                source="OSINTLEAK",
                breach_name=item.get("source", "Unknown"),
                data_classes=item.get("type", "credentials"),
                breach_date=item.get("date", "Unknown"),
                raw_json=str(item),
            )
        )
    return records


def _scrape_paste_sites(identifier: str) -> List[BreachRecord]:
    """
    Search psbdmp.ws paste dumps for an identifier.

    No API key required.

    Args:
        identifier: Email or username to search.

    Returns:
        List of BreachRecord objects from paste sources.
    """
    response = _get(f"{PASTE_BASE}/{identifier}")
    if response is None or response.status_code != 200:
        return []

    data = response.json()
    if not isinstance(data, list):
        return []

    records = []
    for item in data[:10]:
        records.append(
            BreachRecord(
                identifier=identifier,
                source="PASTE",
                breach_name=item.get("id", "paste"),
                data_classes="unknown",
                breach_date=item.get("time", "Unknown"),
                raw_json=str(item),
            )
        )
    return records


def scrape_all(identifier: str) -> int:
    """
    Poll all configured free sources for an identifier and cache results.

    Sources without API keys are skipped silently — no errors thrown.
    Results are deduplicated before caching.

    Args:
        identifier: Email, username, or phone to search.

    Returns:
        Total number of new records cached.
    """
    scrapers = [
        _scrape_hibp,
        _scrape_leakcheck,
        _scrape_breachdirectory,
        _scrape_emailrep,
        _scrape_osintleak,
        _scrape_paste_sites,
    ]

    total = 0
    seen = set()

    for scraper in scrapers:
        try:
            records = scraper(identifier)
            for record in records:
                key = (record.source, record.breach_name)
                if key in seen:
                    continue
                seen.add(key)
                cache_breach(record)
                total += 1
        except Exception as exc:  # pylint: disable=broad-except
            print(f"  Scraper error ({scraper.__name__}): {exc}")
            continue

    return total
