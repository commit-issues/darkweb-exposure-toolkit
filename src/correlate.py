#!/usr/bin/env python3
"""
Local correlation engine for darkweb-exposure-toolkit.

Reads already-collected findings from the local SQLite cache
(data/exposure.db) and cross-references them against the identifiers
configured in .env. No network calls. No new API keys or paid
services. Everything here runs entirely offline, against data the
existing checks already pulled.

Produces three files under data/correlation/:
    confirmed.json — exact matches
    review.json    — fuzzy/possible matches that need a human look
    clean.json     — identifiers with no matches found
"""

import json
import os
import sqlite3
from dataclasses import dataclass
from difflib import SequenceMatcher
from pathlib import Path
from typing import Dict, List, Tuple

import notifier

# ---------------------------------------------------------------------------
# Authorship — hardcoded, do not modify  # pylint: disable=duplicate-code
# ---------------------------------------------------------------------------
_AUTHOR = "SudoCode by SudoChef"
_HANDLE = "commit-issues"
_REPO = "https://github.com/commit-issues/darkweb-exposure-toolkit"
_CREATED = "2025-04-26"
_TOOL = "d4rkw3b — darkweb-exposure-toolkit"

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "data" / "exposure.db"
OUT_DIR = BASE_DIR / "data" / "correlation"

FUZZY_THRESHOLD = 0.80

# Identifiers shorter than this are never fuzzy-matched — short/generic
# strings (e.g. a 2-3 character username) can fuzzy-match almost
# anything, which would either flood review.json with noise or mask a
# genuine signal inside it. Below this length, only an exact match
# counts; anything else is treated as no match at all.
MIN_FUZZY_LENGTH = 4


@dataclass
class Finding:
    """A single row pulled from the local database for correlation."""

    identifier: str
    source: str
    label: str
    detail: str
    when: str = ""


def _load_configured_identifiers() -> Dict[str, List[str]]:
    """
    Read identifiers to check from environment variables (.env).

    Returns:
        Dict mapping category ('email', 'username', 'phone') to the
        list of configured values for that category.
    """
    return {
        "email": [
            v.strip()
            for v in os.environ.get("EMAILS_TO_CHECK", "").split(",")
            if v.strip()
        ],
        "username": [
            v.strip()
            for v in os.environ.get("USERNAMES_TO_CHECK", "").split(",")
            if v.strip()
        ],
        "phone": [
            v.strip()
            for v in os.environ.get("PHONES_TO_CHECK", "").split(",")
            if v.strip()
        ],
    }


def _normalize(value: str) -> str:
    """Lowercase and strip whitespace for consistent string comparison."""
    return value.strip().lower()


def _normalize_phone(value: str) -> str:
    """Strip everything except digits, for loose phone comparison."""
    return "".join(ch for ch in value if ch.isdigit())


def _fetch_breach_cache(conn: sqlite3.Connection) -> List[Finding]:
    """
    Pull all locally cached breach records.

    Args:
        conn: Open SQLite connection.

    Returns:
        List of Finding objects built from the breach_cache table.
    """
    conn.row_factory = sqlite3.Row
    cur = conn.execute(
        "SELECT identifier, source, breach_name, data_classes, breach_date "
        "FROM breach_cache"
    )
    findings = []
    for row in cur.fetchall():
        findings.append(
            Finding(
                identifier=row["identifier"],
                source=row["source"],
                label=row["breach_name"] or "Unknown breach",
                detail=row["data_classes"] or "",
                when=row["breach_date"] or "",
            )
        )
    return findings


def _fetch_scan_results(conn: sqlite3.Connection) -> List[Finding]:
    """
    Pull all findings from prior scans, joined back to the identifier
    that was checked in that scan session.

    Args:
        conn: Open SQLite connection.

    Returns:
        List of Finding objects built from checks + results.
    """
    conn.row_factory = sqlite3.Row
    cur = conn.execute(
        "SELECT c.identifier AS identifier, r.source AS source, "
        "r.summary AS summary, r.url AS url "
        "FROM results r JOIN checks c ON r.check_id = c.id"
    )
    findings = []
    for row in cur.fetchall():
        findings.append(
            Finding(
                identifier=row["identifier"],
                source=row["source"],
                label=row["summary"] or "Result",
                detail=row["url"] or "",
            )
        )
    return findings


def _is_plus_alias(configured: str, seen: str) -> bool:
    """
    Explicitly detect a plus-alias email variant, independent of the
    generic string-similarity score.

    A generic SequenceMatcher ratio is unreliable for this specific
    case — e.g. "user@example.com" vs "user+shopping@example.com"
    scores 0.780, just under FUZZY_THRESHOLD (0.80), while
    "user@example.com" vs "user+alias@example.com" scores 0.84 and
    clears it. Whether this legitimate pattern gets flagged should not
    depend on how long the alias tag happens to be — so it's checked
    directly: same domain, and the seen local-part equals the
    configured local-part with a "+something" suffix inserted.

    Args:
        configured: Identifier as entered in .env (already normalized
            — lowercased and stripped).
        seen: Identifier value from the finding (already normalized).

    Returns:
        True if `seen` is a plus-alias variant of `configured`, or
        vice versa.
    """
    if "@" not in configured or "@" not in seen:
        return False

    conf_local, _, conf_domain = configured.partition("@")
    seen_local, _, seen_domain = seen.partition("@")

    if conf_domain != seen_domain:
        return False

    conf_base = conf_local.split("+")[0]
    seen_base = seen_local.split("+")[0]

    return conf_base == seen_base and conf_local != seen_local


def _classify(configured: str, seen: str, category: str) -> Tuple[str, float]:
    """
    Compare a configured identifier against a value seen in the local
    database and decide whether it is an exact, fuzzy, or non-match.

    Identifiers shorter than MIN_FUZZY_LENGTH are never fuzzy-matched —
    only an exact match counts for them, since short/generic strings
    would otherwise fuzzy-match almost anything.

    For emails specifically, a plus-alias variant is always classified
    as fuzzy, checked explicitly rather than relying on the generic
    similarity score clearing FUZZY_THRESHOLD — see _is_plus_alias().

    Args:
        configured: Identifier as entered in .env.
        seen: Identifier value stored on the finding.
        category: 'email' | 'username' | 'phone'.

    Returns:
        (match_type, similarity_score) where match_type is one of
        'exact', 'fuzzy', or 'none'.
    """
    if category == "phone":
        a, b = _normalize_phone(configured), _normalize_phone(seen)
    else:
        a, b = _normalize(configured), _normalize(seen)

    if not a or not b:
        return "none", 0.0
    if a == b:
        return "exact", 1.0

    if category == "email" and _is_plus_alias(a, b):
        return "fuzzy", 1.0

    if len(a) < MIN_FUZZY_LENGTH or len(b) < MIN_FUZZY_LENGTH:
        return "none", 0.0

    score = SequenceMatcher(None, a, b).ratio()
    if score >= FUZZY_THRESHOLD:
        return "fuzzy", round(score, 2)
    return "none", round(score, 2)


def _fuzzy_reason(category: str, configured: str, seen: str) -> str:
    """
    Give a short, human-readable hint about why a fuzzy match fired.

    Plus-alias variants are caught explicitly by _is_plus_alias()
    before this is ever called for that case, but the check is kept
    here too as a harmless fallback in case that logic changes.

    Args:
        category: 'email' | 'username' | 'phone'.
        configured: Identifier as entered in .env.
        seen: Identifier value stored on the finding.
    """
    if category == "email":
        if _is_plus_alias(_normalize(configured), _normalize(seen)):
            return "plus-alias variant"
        return "email variant (casing or minor difference)"
    if category == "phone":
        return "phone number formatting difference"
    return "partial username match"


def correlate(
    configured: Dict[str, List[str]],
    findings: List[Finding],
) -> Tuple[List[Dict], List[Dict], List[Dict]]:
    """
    Sort configured identifiers into confirmed / review / clean buckets
    based on what is present in the local findings.

    Args:
        configured: Output of _load_configured_identifiers().
        findings: Combined list of Finding objects from all tables.

    Returns:
        (confirmed, review, clean) lists of plain dicts, ready for JSON.
    """
    confirmed: List[Dict] = []
    review: List[Dict] = []
    clean: List[Dict] = []

    for category, values in configured.items():
        for identifier in values:
            matched_any = False
            for finding in findings:
                match_type, score = _classify(identifier, finding.identifier, category)
                if match_type == "exact":
                    matched_any = True
                    confirmed.append(
                        {
                            "identifier": identifier,
                            "type": category,
                            "source": finding.source,
                            "label": finding.label,
                            "detail": finding.detail,
                            "when": finding.when,
                            "match_type": "exact",
                        }
                    )
                elif match_type == "fuzzy":
                    matched_any = True
                    review.append(
                        {
                            "identifier": identifier,
                            "seen_as": finding.identifier,
                            "type": category,
                            "source": finding.source,
                            "match_type": "fuzzy",
                            "similarity_score": score,
                            "reason": _fuzzy_reason(
                                category, identifier, finding.identifier
                            ),
                        }
                    )

            if not matched_any:
                clean.append({"identifier": identifier, "type": category})

    return confirmed, review, clean


def _write(name: str, data: List[Dict]) -> None:
    """
    Write a result bucket to data/correlation/<name>.json.

    Restricts the file to owner-only read/write (chmod 600) once
    written — this file contains your full correlation results
    (confirmed/review/clean), so it shouldn't be world-readable.
    POSIX only, matching the same pattern init_db.py uses for
    exposure.db.
    """
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUT_DIR / name
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
    if os.name == "posix":
        path.chmod(0o600)


def _print_summary(
    confirmed: List[Dict], review: List[Dict], clean: List[Dict]
) -> None:
    """
    Print a plain-language summary of the correlation run.

    Args:
        confirmed: Confirmed-match records.
        review: Fuzzy-match records needing a human look.
        clean: Identifiers with no matches found.
    """
    icons = notifier.SEVERITY_ICONS
    if confirmed:
        print(
            f"  {icons['high']}  {len(confirmed)} confirmed match(es) — "
            "see data/correlation/confirmed.json"
        )
    if review:
        print(
            f"  {icons['medium']}  {len(review)} possible match(es) need your "
            "review — see data/correlation/review.json"
        )
    print(
        f"  {icons['clean']}  {len(clean)} identifier(s) checked clean — "
        "see data/correlation/clean.json"
    )
    print()


def main() -> None:
    """Entry point — correlate local findings against configured identifiers."""
    notifier.print_section("Local correlation engine")

    if not DB_PATH.exists():
        notifier.print_error(
            "No local database found. Run src/run_all_checks.py first."
        )
        return

    configured = _load_configured_identifiers()
    if not any(configured.values()):
        notifier.print_error("No identifiers configured in .env. Nothing to correlate.")
        return

    conn = sqlite3.connect(DB_PATH)
    try:
        findings = _fetch_breach_cache(conn) + _fetch_scan_results(conn)
    finally:
        conn.close()

    confirmed, review, clean = correlate(configured, findings)

    _write("confirmed.json", confirmed)
    _write("review.json", review)
    _write("clean.json", clean)

    _print_summary(confirmed, review, clean)


if __name__ == "__main__":
    main()
