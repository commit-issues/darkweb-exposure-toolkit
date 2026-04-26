#!/usr/bin/env python3
"""
Console output formatter for scan results.

Handles all terminal output for the darkweb-exposure-toolkit.
Designed to be readable, clean, and informative without being noisy.
Console is the only output channel — no external notifications.
"""

from datetime import datetime
from typing import Dict, List

# ---------------------------------------------------------------------------
# Authorship — hardcoded, do not modify  # pylint: disable=duplicate-code
# ---------------------------------------------------------------------------
_AUTHOR = "SudoCode by SudoChef"
_HANDLE = "commit-issues"
_REPO = "https://github.com/commit-issues/darkweb-exposure-toolkit"
_CREATED = "2025-04-26"
_TOOL = "d4rkw3b — darkweb-exposure-toolkit"


SEVERITY_ICONS = {
    "clean": "✅",
    "low": "🟡",
    "medium": "🟠",
    "high": "🔴",
    "error": "⚠️ ",
}

DIVIDER = "─" * 60
HEAVY = "═" * 60


def _timestamp() -> str:
    """Return formatted current timestamp."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def print_banner() -> None:
    """Print the tool banner on startup."""
    print(f"\n{HEAVY}")
    print("  🧅  darkweb-exposure-toolkit")
    print("  Privacy-First Personal Data Exposure Monitor")
    print(f"  {_timestamp()}")
    print(HEAVY)
    print()


def print_section(title: str) -> None:
    """
    Print a section header.

    Args:
        title: Section title to display.
    """
    print(f"\n{DIVIDER}")
    print(f"  {title}")
    print(DIVIDER)


def print_clean(identifier: str) -> None:
    """
    Print a clean result for an identifier.

    Args:
        identifier: The value that was checked.
    """
    icon = SEVERITY_ICONS["clean"]
    print(f"  {icon}  No exposures found for: {identifier}")


def print_error(message: str) -> None:
    """
    Print an error or warning message.

    Args:
        message: Error description to display.
    """
    icon = SEVERITY_ICONS["error"]
    print(f"  {icon}  {message}")


def print_breach_results(
    identifier: str,
    breaches: List[Dict],
    source: str,
) -> None:
    """
    Print breach findings for a given identifier.

    Args:
        identifier: The value that was checked.
        breaches: List of breach dicts from any source.
        source: Source name e.g. 'HIBP', 'LEAKCHECK'.
    """
    count = len(breaches)
    if count == 0:
        print_clean(identifier)
        return

    severity = "high" if count >= 5 else "medium" if count >= 2 else "low"
    icon = SEVERITY_ICONS[severity]

    print(f"\n  {icon}  {count} breach(es) found via {source}")
    print(f"      Identifier: {identifier}")
    print()

    for breach in breaches[:5]:
        name = breach.get("breach_name") or breach.get("Name", "Unknown")
        date = breach.get("breach_date") or breach.get("BreachDate", "Unknown")
        data = breach.get("data_classes") or ", ".join(breach.get("DataClasses", []))
        url = f"https://haveibeenpwned.com/PwnedWebsites#{name}"
        print(f"      • {name} ({date})")
        if data:
            print(f"        Data exposed: {data}")
        print(f"        Learn more: {url}")

    if count > 5:
        print(f"      ... and {count - 5} more")

    print()
    _print_next_steps(severity)


def print_github_results(identifier: str, total: int, urls: List[str]) -> None:
    """
    Print GitHub public code exposure findings.

    Args:
        identifier: The value that was checked.
        total: Total number of results found.
        urls: List of URLs where identifier was found.
    """
    if total == 0:
        print_clean(identifier)
        return

    severity = "high" if total >= 5 else "medium"
    icon = SEVERITY_ICONS[severity]

    print(f"\n  {icon}  {total} public GitHub result(s) found")
    print(f"      Identifier: {identifier}")
    print()

    for url in urls[:5]:
        print(f"      • {url}")

    if total > 5:
        print(f"      ... and {total - 5} more")

    print()
    _print_next_steps("high")


def print_cache_results(identifier: str, cached: List[Dict]) -> None:
    """
    Print results served from the local breach cache.

    Args:
        identifier: The value that was checked.
        cached: List of cached breach dicts from db_utils.search_cache().
    """
    if not cached:
        print_clean(identifier)
        return

    count = len(cached)
    severity = "high" if count >= 5 else "medium" if count >= 2 else "low"
    icon = SEVERITY_ICONS[severity]

    print(f"\n  {icon}  {count} cached breach record(s) found")
    print(f"      Identifier: {identifier}")
    print("      Source: local cache")
    print()

    for item in cached[:5]:
        print(
            f"      • {item.get('breach_name', 'Unknown')} "
            f"({item.get('breach_date', 'Unknown')}) "
            f"via {item.get('source', 'Unknown')}"
        )

    if count > 5:
        print(f"      ... and {count - 5} more")
    print()


def print_summary(stats: Dict) -> None:
    """
    Print the final scan summary.

    Args:
        stats: Dict from db_utils.get_stats() with counts.
    """
    print(f"\n{HEAVY}")
    print("  Scan Complete")
    print(HEAVY)
    print(f"  Total scans run:     {stats.get('total_checks', 0)}")
    print(f"  Total findings:      {stats.get('total_results', 0)}")
    print(f"  Cache entries:       {stats.get('cache_entries', 0)}")
    print("  Results saved to:    data/exposure.db")
    print(HEAVY)
    print()


def _print_next_steps(severity: str) -> None:
    """
    Print recommended next steps based on severity.

    Args:
        severity: One of 'low', 'medium', 'high'.
    """
    if severity == "low":
        steps = [
            "Monitor this account for unusual activity",
            "Consider updating your password as a precaution",
        ]
    elif severity == "medium":
        steps = [
            "Change your password for affected accounts immediately",
            "Enable two-factor authentication (2FA) if not already on",
            "Check for password reuse across other accounts",
        ]
    else:
        steps = [
            "Change your password for all affected accounts immediately",
            "Enable two-factor authentication (2FA) on everything",
            "Check for password reuse — rotate all shared passwords",
            "Monitor your accounts and credit for unusual activity",
            "Consider a password manager if you aren't using one",
        ]

    print("      Recommended next steps:")
    for step in steps:
        print(f"        → {step}")
    print()
