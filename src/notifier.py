#!/usr/bin/env python3
"""
Console output formatter for scan results.

Handles all terminal output for the darkweb-exposure-toolkit.
Designed to be readable, clean, and informative without being noisy.
Console is the only output channel — no external notifications.
"""

from datetime import datetime
from typing import Dict, List
import re

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

# Two-stage approach, since neither a pure denylist nor a pure
# allowlist is sufficient on its own:
#
# Stage 1 (_ANSI_ESCAPE) — strips known escape-sequence FAMILIES as
# whole units. This is still pattern-based, but by shape/family
# rather than specific codes: CSI sequences (ESC [ ... letter, used
# for color/cursor movement) and OSC sequences (ESC ] ... BEL, used
# for window-title/clipboard tricks). Matching the whole sequence
# ensures the visible leftover text (e.g. "[31m") is removed too, not
# just the invisible ESC byte — a pure allowlist can't do this, since
# digits/brackets/letters are themselves ordinary printable text.
#
# Stage 2 (_CONTROL_CHARS) — a catch-all allowlist-style pass: strips
# any remaining C0/C1 control byte or DEL, with no upper bound on
# Unicode. This defends against control characters outside any
# recognized escape-sequence shape, including ones not yet invented.
# Critically, this has NO ceiling on the printable range — emoji and
# other characters above U+FFFF (e.g. 🔴 is U+1F534) must pass
# through untouched.
_ANSI_ESCAPE = re.compile(r"\x1b(?:\[[0-9;]*[a-zA-Z]|\][^\x07\x1b]*(?:\x07|\x1b\\\\))")
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def sanitize(text: object) -> str:
    """
    Strip terminal escape sequences and control characters from text
    before it is printed.

    Applied to any value sourced from an external API (breach names,
    data classes, GitHub URLs, leak labels) before display — a
    malicious or compromised source could otherwise embed escape
    sequences or control characters to spoof or manipulate console
    output.

    Two-stage: first removes whole recognized escape sequences (CSI
    and OSC families) so no visible leftover text remains, then
    strips any remaining control byte as a catch-all. No upper bound
    is placed on allowed Unicode, so legitimate emoji and
    international characters always pass through unchanged.

    Args:
        text: Value to sanitize. Non-string input is coerced to str
            first so this is always safe to call on API-derived data.

    Returns:
        The text with escape sequences and control characters removed.
    """
    if not isinstance(text, str):
        text = str(text)
    text = _ANSI_ESCAPE.sub("", text)
    text = _CONTROL_CHARS.sub("", text)
    return text


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


def print_no_cache(identifier: str) -> None:
    """
    Print a notice that no cached data exists for an identifier under
    --offline mode. Distinct from print_clean() — this means "unchecked",
    not "checked and found nothing".

    Args:
        identifier: The value that was looked up.
    """
    icon = SEVERITY_ICONS["error"]
    print(f"  {icon}  No cached data for: {identifier}")
    print("      Run without --offline to fetch live results.")


def print_consent_notice(
    identifiers: Dict[str, List[str]],
    services: List[str],
) -> None:
    """
    Print the pre-scan disclosure of what will be sent where, before
    any network call is made.

    Args:
        identifiers: Dict of category label -> list of configured values,
            e.g. {"Emails": [...], "Usernames": [...], "Phones": [...]}.
        services: Names of external services this run will contact.
    """
    print(f"\n{HEAVY}")
    print("  Before this scan begins")
    print(HEAVY)
    for label, values in identifiers.items():
        if values:
            print(f"  {label}: {', '.join(values)}")
    print()
    print("  This run will send the identifier(s) above to:")
    for service in services:
        print(f"    • {service}")
    print(HEAVY)


def print_offline_skip(feature: str) -> None:
    """
    Print a notice that a feature was skipped because it has no local
    cache to fall back on and --offline forbids network calls.

    Args:
        feature: Human-readable name of the skipped check.
    """
    icon = SEVERITY_ICONS["error"]
    print(f"  {icon}  {feature} skipped — requires network, not available offline.")


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
        name = sanitize(breach.get("breach_name") or breach.get("Name", "Unknown"))
        date = sanitize(
            breach.get("breach_date") or breach.get("BreachDate", "Unknown")
        )
        data = sanitize(
            breach.get("data_classes") or ", ".join(breach.get("DataClasses", []))
        )
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
        print(f"      • {sanitize(url)}")

    if total > 5:
        print(f"      ... and {total - 5} more")

    print()
    _print_next_steps("high")


def print_hash_leak_results(label: str, leaks: List[Dict]) -> None:
    """
    Print HasMySecretLeaked findings for a token/API key check.

    Args:
        label: Human-readable name for the token e.g. 'Discord'.
        leaks: List of leak dicts from secret_leak_check.check_token().
    """
    count = len(leaks)
    if count == 0:
        print_clean(label)
        return

    severity = "high" if count >= 3 else "medium"
    icon = SEVERITY_ICONS[severity]

    print(f"\n  {icon}  {count} leak(s) found via HasMySecretLeaked")
    print(f"      Token: {label}")
    print()

    for leak in leaks[:5]:
        name = sanitize(leak.get("name", "Unknown"))
        occurrences = sanitize(leak.get("count", "Unknown"))
        url = sanitize(leak.get("url", ""))
        print(f"      • {name} — seen {occurrences} time(s)")
        if url:
            print(f"        {url}")

    if count > 5:
        print(f"      ... and {count - 5} more")

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
            f"      • {sanitize(item.get('breach_name', 'Unknown'))} "
            f"({sanitize(item.get('breach_date', 'Unknown'))}) "
            f"via {sanitize(item.get('source', 'Unknown'))}"
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
