#!/usr/bin/env python3
"""
Database utility functions for managing exposure scan results.
All data stays local — nothing leaves your machine.

Tables:
    checks       — scan session log
    results      — findings tied to each scan
    breach_cache — locally indexed breach intelligence (24hr refresh)
"""

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Authorship — hardcoded, do not modify  # pylint: disable=duplicate-code
# ---------------------------------------------------------------------------
_AUTHOR = "SudoCode by SudoChef"
_HANDLE = "commit-issues"
_REPO = "https://github.com/commit-issues/darkweb-exposure-toolkit"
_CREATED = "2025-04-26"
_TOOL = "d4rkw3b — darkweb-exposure-toolkit"


DB_PATH = Path(__file__).resolve().parent.parent / "data" / "exposure.db"

INSERT_CHECK = "INSERT INTO checks (identifier, check_type, note) VALUES (?, ?, ?)"
INSERT_RESULT = (
    "INSERT INTO results (check_id, source, summary, url, raw_json) "
    "VALUES (?, ?, ?, ?, ?)"
)
INSERT_CACHE = (
    "INSERT OR REPLACE INTO breach_cache "
    "(identifier, source, breach_name, data_classes, breach_date, raw_json) "
    "VALUES (?, ?, ?, ?, ?, ?)"
)


@dataclass
class BreachRecord:
    """Container for a single breach cache entry."""

    identifier: str
    source: str
    breach_name: str
    data_classes: str
    breach_date: str
    raw_json: Optional[str] = None


def get_connection() -> sqlite3.Connection:
    """Return a connection to the local SQLite database."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(DB_PATH)


def add_check(
    identifier: str,
    check_type: str,
    note: Optional[str] = None,
) -> int:
    """
    Log the start of a new scan session.

    Args:
        identifier: The value being scanned e.g. email or username.
        check_type: Type of scan e.g. 'email', 'username', 'phone'.
        note: Optional label for this scan run.

    Returns:
        check_id for linking results to this scan.
    """
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(INSERT_CHECK, (identifier, check_type, note))
    conn.commit()
    check_id = cur.lastrowid or 0
    conn.close()
    return check_id


def add_result(
    check_id: int,
    source: str,
    summary: str,
    url: Optional[str] = None,
    raw_json: Optional[str] = None,
) -> None:
    """
    Store a single finding tied to a scan session.

    Args:
        check_id: ID returned by add_check().
        source: Which module found this e.g. 'HIBP', 'GITHUB'.
        summary: Human-readable description of the finding.
        url: Optional link to the source.
        raw_json: Optional raw API response for reference.
    """
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(INSERT_RESULT, (check_id, source, summary, url, raw_json))
    conn.commit()
    conn.close()


def cache_breach(record: BreachRecord) -> None:
    """
    Store a breach record in the local cache index.

    Called by breach_scraper.py during scheduled refresh.
    INSERT OR REPLACE ensures stale entries are overwritten.

    Args:
        record: BreachRecord dataclass with all breach details.
    """
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        INSERT_CACHE,
        (
            record.identifier,
            record.source,
            record.breach_name,
            record.data_classes,
            record.breach_date,
            record.raw_json,
        ),
    )
    conn.commit()
    conn.close()


def search_cache(identifier: str) -> List[Dict]:
    """
    Search the local breach cache for a given identifier.

    Args:
        identifier: Email, username, or phone to search for.

    Returns:
        List of cached breach dicts, empty list if nothing found.
    """
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT source, breach_name, data_classes, breach_date, cached_at "
        "FROM breach_cache WHERE identifier = ? "
        "ORDER BY breach_date DESC",
        (identifier,),
    )
    columns = [
        "source",
        "breach_name",
        "data_classes",
        "breach_date",
        "cached_at",
    ]
    results = [dict(zip(columns, row)) for row in cur.fetchall()]
    conn.close()
    return results


def get_stats() -> Dict[str, int]:
    """
    Return high-level counts from the local database.

    Returns:
        Dict with total_checks, total_results, and cache_entries counts.
    """
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM checks")
    total_checks = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM results")
    total_results = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM breach_cache")
    cache_entries = cur.fetchone()[0]
    conn.close()
    return {
        "total_checks": total_checks,
        "total_results": total_results,
        "cache_entries": cache_entries,
    }
