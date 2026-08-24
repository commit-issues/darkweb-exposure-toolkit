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

Hardening notes (threat model: every one of these six sources is
treated as potentially compromised, spoofed, or MITM'd, since this
tool has no control over their infrastructure):
  - Redirects are never followed (allow_redirects=False) — these are
    fixed, known-good base URLs; a redirect is either a
    misconfiguration or an SSRF attempt and is rejected either way.
  - Response size is capped before parsing (MAX_RESPONSE_BYTES) to
    prevent a malicious/compromised source from exhausting memory.
  - JSON parsing failures are caught explicitly, not left to an outer
    broad exception handler.
  - Every parsed item is type-checked (must be a dict) before any
    .get() call — a source returning an unexpected shape (e.g. a list
    of strings instead of dicts) is skipped, not trusted.
"""

import json
import os
import re
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote

import requests

import notifier
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

# 5 MB — generous for any legitimate breach-lookup response (these are
# small JSON records, not bulk data dumps), but a firm ceiling against
# a compromised/malicious source trying to exhaust memory.
MAX_RESPONSE_BYTES = 5_000_000

# API keys must look like reasonable key/token material — no
# whitespace or control characters. This is a light sanity check on
# top of whatever protection the requests library itself provides
# against header injection; a malformed .env value is rejected here
# rather than relied upon to fail safely somewhere else.
_KEY_RE = re.compile(r"^[A-Za-z0-9._\-]+$")

HIBP_BASE = "https://haveibeenpwned.com/api/v3"
LEAKCHECK_BASE = "https://leakcheck.io/api/public"
BREACHDIR_BASE = "https://breachdirectory.org/api"
EMAILREP_BASE = "https://emailrep.io"
OSINTLEAK_BASE = "https://api.osintleak.com/v1"
PASTE_BASE = "https://psbdmp.ws/api/search"

_HEADERS: Dict[str, str] = {
    "User-Agent": "darkweb-exposure-toolkit/2.0 (personal-security-scanner)",
}


def _clean_key(raw_key: str) -> str:
    """
    Validate an API key read from the environment before it's used in
    any request header.

    Args:
        raw_key: Value read from os.getenv() for an API key.

    Returns:
        The key unchanged if it passes the sanity check, or an empty
        string if it contains unexpected characters (treated the same
        as "not configured" — the source is skipped rather than
        sending a malformed header).
    """
    if not raw_key:
        return ""
    if not _KEY_RE.match(raw_key):
        notifier.print_error(
            "An API key in .env contains unexpected characters and will "
            "be ignored. Check your .env file for stray whitespace or "
            "corruption."
        )
        return ""
    return raw_key


_HIBP_KEY = _clean_key(os.getenv("HIBP_API_KEY", ""))
_EMAILREP_KEY = _clean_key(os.getenv("EMAILREP_API_KEY", ""))
_OSINTLEAK_KEY = _clean_key(os.getenv("OSINTLEAK_API_KEY", ""))

_HIBP_HEADERS = {**_HEADERS, "hibp-api-key": _HIBP_KEY} if _HIBP_KEY else _HEADERS
_EMAILREP_HEADERS = {**_HEADERS, "Key": _EMAILREP_KEY} if _EMAILREP_KEY else _HEADERS
_OSINTLEAK_HEADERS = (
    {**_HEADERS, "Authorization": f"Bearer {_OSINTLEAK_KEY}"}
    if _OSINTLEAK_KEY
    else _HEADERS
)


@dataclass
class ScrapeSummary:
    """
    Aggregate result of scrape_all() across all configured sources.

    A source is "attempted" only if it actually made a network call —
    sources skipped because no API key is configured (or the identifier
    doesn't apply, e.g. a phone number sent to an email-only source)
    are not counted, so all_failed can't be triggered by config choices
    alone.
    """

    records_added: int
    sources_attempted: int
    sources_succeeded: int

    @property
    def all_failed(self) -> bool:
        """True only if every source that was actually tried failed."""
        return self.sources_attempted > 0 and self.sources_succeeded == 0


# Each _scrape_* function returns (records, ok):
#   ok = None  -> not attempted (no key configured / identifier not applicable)
#   ok = False -> attempted, network/transport failure
#   ok = True  -> attempted, call succeeded (records may still be empty — clean)
_ScrapeResult = Tuple[List[BreachRecord], Optional[bool]]


def _get(
    url: str,
    headers: Optional[Dict] = None,
    params: Optional[Dict] = None,
) -> Optional[requests.Response]:
    """
    Shared GET with timeout, redirect blocking, size cap, and
    connection error handling.

    Args:
        url: Full request URL.
        headers: Optional request headers.
        params: Optional query parameters.

    Returns:
        Response object or None on error, oversized response, or if a
        redirect was attempted.
    """
    try:
        response = requests.get(
            url,
            headers=headers or _HEADERS,
            params=params,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
        )
        time.sleep(RATE_LIMIT_SLEEP)

        if response.is_redirect or response.status_code in (301, 302, 303, 307, 308):
            notifier.print_error(f"Refused redirect from a fixed API endpoint: {url}")
            return None

        if len(response.content) > MAX_RESPONSE_BYTES:
            notifier.print_error(
                f"Response from {url} exceeded the maximum allowed size "
                f"({MAX_RESPONSE_BYTES:,} bytes) and was discarded."
            )
            return None

        return response
    except requests.exceptions.ConnectionError:
        notifier.print_error(f"Connection error: {url}")
        return None
    except requests.exceptions.Timeout:
        notifier.print_error(f"Timeout: {url}")
        return None
    except requests.exceptions.RequestException as exc:
        notifier.print_error(f"Request error: {exc}")
        return None


def _safe_json(response: requests.Response, url: str) -> Optional[object]:
    """
    Parse a response body as JSON, catching decode failures explicitly
    rather than letting them propagate as an uncaught exception.

    Args:
        response: A Response already passed through _get()'s size and
            redirect checks.
        url: The request URL, for a clear error message.

    Returns:
        The parsed JSON value (list, dict, etc.), or None if the body
        was not valid JSON.
    """
    try:
        return response.json()  # type: ignore[no-any-return]
    except (ValueError, json.JSONDecodeError):
        notifier.print_error(f"Received invalid (non-JSON) response from {url}.")
        return None


def _scrape_hibp(  # pylint: disable=too-many-return-statements
    identifier: str,
) -> _ScrapeResult:  # pylint: disable=too-many-return-statements
    """
    Scrape HIBP breach data for an email or username.

    Requires HIBP_API_KEY in .env. Skipped silently if not set.

    Each early return below is a distinct validation gate (no key
    configured, network failure, not-found, bad status, invalid JSON,
    unexpected shape) rather than tangled logic — a guard-clause chain
    defending against a compromised or malformed HIBP response at
    every stage before any data is trusted.

    Args:
        identifier: Email or username to search.

    Returns:
        (records, ok) — see _ScrapeResult.
    """
    if not _HIBP_KEY:
        return [], None

    url = f"{HIBP_BASE}/breachedaccount/{quote(identifier, safe='')}"
    response = _get(
        url,
        headers=_HIBP_HEADERS,
        params={"truncateResponse": "false"},
    )
    if response is None:
        return [], False
    if response.status_code == 404:
        return [], True
    if response.status_code != 200:
        return [], False

    data = _safe_json(response, url)
    if data is None:
        return [], False
    if not isinstance(data, list):
        notifier.print_error("HIBP returned an unexpected response shape.")
        return [], False

    records = []
    for breach in data:
        if not isinstance(breach, dict):
            continue
        records.append(
            BreachRecord(
                identifier=identifier,
                source="HIBP",
                breach_name=breach.get("Name", "Unknown"),
                data_classes=", ".join(breach.get("DataClasses", [])),
                breach_date=breach.get("BreachDate", "Unknown"),
                raw_json=json.dumps(breach),
            )
        )
    return records, True


def _scrape_leakcheck(identifier: str) -> _ScrapeResult:
    """
    Scrape LeakCheck free tier for an email or username.

    No API key required for free tier.

    Args:
        identifier: Email or username to search.

    Returns:
        (records, ok) — see _ScrapeResult.
    """
    response = _get(LEAKCHECK_BASE, params={"check": identifier})
    if response is None or response.status_code != 200:
        return [], False

    data = _safe_json(response, LEAKCHECK_BASE)
    if not isinstance(data, dict):
        return [], False
    if not data.get("success") or not data.get("sources"):
        return [], True
    if not isinstance(data["sources"], list):
        notifier.print_error("LeakCheck returned an unexpected response shape.")
        return [], False

    records = []
    for source in data["sources"]:
        if not isinstance(source, dict):
            continue
        records.append(
            BreachRecord(
                identifier=identifier,
                source="LEAKCHECK",
                breach_name=source.get("name", "Unknown"),
                data_classes=source.get("fields", "Unknown"),
                breach_date=source.get("date", "Unknown"),
            )
        )
    return records, True


def _scrape_breachdirectory(identifier: str) -> _ScrapeResult:
    """
    Scrape BreachDirectory free API for an email or username.

    No API key required.

    Args:
        identifier: Email or username to search.

    Returns:
        (records, ok) — see _ScrapeResult.
    """
    response = _get(
        f"{BREACHDIR_BASE}/search",
        params={"func": "auto", "term": identifier},
    )
    if response is None or response.status_code != 200:
        return [], False

    data = _safe_json(response, BREACHDIR_BASE)
    if not isinstance(data, dict):
        return [], False
    results = data.get("result", [])
    if not isinstance(results, list) or not results:
        return [], True

    records = []
    for item in results[:10]:
        if not isinstance(item, dict):
            continue
        sources = item.get("sources") or ["Unknown"]
        breach_name = sources[0] if isinstance(sources, list) and sources else "Unknown"
        fields = item.get("fields", [])
        records.append(
            BreachRecord(
                identifier=identifier,
                source="BREACHDIR",
                breach_name=breach_name,
                data_classes=", ".join(fields) if isinstance(fields, list) else "",
                breach_date="Unknown",
                raw_json=json.dumps(item),
            )
        )
    return records, True


def _scrape_emailrep(identifier: str) -> _ScrapeResult:
    """
    Scrape Emailrep.io for email reputation and breach history.

    Requires EMAILREP_API_KEY in .env for higher rate limits.
    Works without a key at reduced rate. Only applies to email identifiers.

    Args:
        identifier: Email address to search.

    Returns:
        (records, ok) — see _ScrapeResult.
    """
    if "@" not in identifier:
        return [], None

    url = f"{EMAILREP_BASE}/{quote(identifier, safe='')}"
    response = _get(url, headers=_EMAILREP_HEADERS)
    if response is None or response.status_code != 200:
        return [], False

    data = _safe_json(response, url)
    if not isinstance(data, dict):
        return [], False

    details = data.get("details")
    if not isinstance(details, dict) or not details.get("data_breach"):
        return [], True

    return [
        BreachRecord(
            identifier=identifier,
            source="EMAILREP",
            breach_name="Data breach confirmed",
            data_classes=f"Last breach: {details.get('last_seen', 'Unknown')}",
            breach_date=details.get("first_seen", "Unknown"),
            raw_json=json.dumps(data),
        )
    ], True


def _scrape_osintleak(identifier: str) -> _ScrapeResult:
    """
    Scrape OSINTLeak free starter for stealer logs and dark web data.

    Requires OSINTLEAK_API_KEY in .env. Skipped silently if not set.

    Args:
        identifier: Email or username to search.

    Returns:
        (records, ok) — see _ScrapeResult.
    """
    if not _OSINTLEAK_KEY:
        return [], None

    url = f"{OSINTLEAK_BASE}/search"
    response = _get(
        url,
        headers=_OSINTLEAK_HEADERS,
        params={"query": identifier},
    )
    if response is None or response.status_code != 200:
        return [], False

    data = _safe_json(response, url)
    if not isinstance(data, dict):
        return [], False
    results = data.get("results", [])
    if not isinstance(results, list):
        notifier.print_error("OSINTLeak returned an unexpected response shape.")
        return [], False

    records = []
    for item in results[:10]:
        if not isinstance(item, dict):
            continue
        records.append(
            BreachRecord(
                identifier=identifier,
                source="OSINTLEAK",
                breach_name=item.get("source", "Unknown"),
                data_classes=item.get("type", "credentials"),
                breach_date=item.get("date", "Unknown"),
                raw_json=json.dumps(item),
            )
        )
    return records, True


def _scrape_paste_sites(identifier: str) -> _ScrapeResult:
    """
    Search psbdmp.ws paste dumps for an identifier.

    No API key required.

    Args:
        identifier: Email or username to search.

    Returns:
        (records, ok) — see _ScrapeResult.
    """
    url = f"{PASTE_BASE}/{quote(identifier, safe='')}"
    response = _get(url)
    if response is None or response.status_code != 200:
        return [], False

    data = _safe_json(response, url)
    if not isinstance(data, list):
        return [], True

    records = []
    for item in data[:10]:
        if not isinstance(item, dict):
            continue
        records.append(
            BreachRecord(
                identifier=identifier,
                source="PASTE",
                breach_name=item.get("id", "paste"),
                data_classes="unknown",
                breach_date=item.get("time", "Unknown"),
                raw_json=json.dumps(item),
            )
        )
    return records, True


def scrape_all(identifier: str) -> ScrapeSummary:
    """
    Poll all configured free sources for an identifier and cache results.

    Sources without API keys (or that don't apply to this identifier type)
    are skipped and not counted as attempted. Results are deduplicated
    before caching.

    Args:
        identifier: Email, username, or phone to search.

    Returns:
        ScrapeSummary with records added and per-source attempt/success
        counts, so callers can tell "genuinely clean" apart from
        "couldn't reach any source".
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
    attempted = 0
    succeeded = 0
    seen = set()

    for scraper in scrapers:
        try:
            records, ok = scraper(identifier)
        except Exception as exc:  # pylint: disable=broad-except
            notifier.print_error(f"Scraper error ({scraper.__name__}): {exc}")
            attempted += 1
            continue

        if ok is None:
            continue

        attempted += 1
        if ok:
            succeeded += 1

        for record in records:
            key = (record.source, record.breach_name)
            if key in seen:
                continue
            seen.add(key)
            cache_breach(record)
            total += 1

    return ScrapeSummary(
        records_added=total,
        sources_attempted=attempted,
        sources_succeeded=succeeded,
    )
