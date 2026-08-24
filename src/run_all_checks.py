#!/usr/bin/env python3
"""
darkweb-exposure-toolkit — Main entry point.

Runs all configured exposure checks against breach databases,
public code search, and the local breach cache. All results
are stored locally. Nothing is shared externally.

Usage:
    python3 src/run_all_checks.py           # full scan
    python3 src/run_all_checks.py --refresh # force cache refresh first
    python3 src/run_all_checks.py --offline # cache-only, zero network calls
"""

# sys is imported alone, ahead of the other standard-library imports
# below, because it must be available before this version check runs —
# everything else in this file assumes Python 3.10+ syntax elsewhere
# in the codebase (see github_search.py's dict[str, str | int] usage).
import sys
import json

if sys.version_info < (3, 10):
    print(
        "\n  \u26a0\ufe0f  darkweb-exposure-toolkit requires Python 3.10 or higher.\n"
        f"      You're running Python "
        f"{sys.version_info.major}.{sys.version_info.minor}.\n"
        "      Please upgrade: https://www.python.org/downloads/\n"
    )
    sys.exit(1)

import argparse  # pylint: disable=wrong-import-position
import importlib  # pylint: disable=wrong-import-position
import getpass  # pylint: disable=wrong-import-position
import os  # pylint: disable=wrong-import-position
from pathlib import Path  # pylint: disable=wrong-import-position
from typing import List, Tuple  # pylint: disable=wrong-import-position

from dotenv import load_dotenv  # pylint: disable=wrong-import-position

# ---------------------------------------------------------------------------
# Authorship — hardcoded, do not modify  # pylint: disable=duplicate-code
# ---------------------------------------------------------------------------
_AUTHOR = "SudoCode by SudoChef"
_HANDLE = "commit-issues"
_REPO = "https://github.com/commit-issues/darkweb-exposure-toolkit"
_CREATED = "2025-04-26"
_TOOL = "d4rkw3b — darkweb-exposure-toolkit"


BASE_DIR = Path(__file__).resolve().parent.parent

# A misconfigured .env (e.g. an accidentally huge EMAILS_TO_CHECK list)
# could otherwise silently burn through free-tier API quota or trigger
# a temporary rate-limit ban with no warning. --force bypasses this.
MAX_IDENTIFIERS = 20

# Load .env BEFORE importing any module that reads os.getenv() at import
# time (github_search.py reads GITHUB_TOKEN, breach_scraper.py reads
# HIBP_API_KEY/EMAILREP_API_KEY/OSINTLEAK_API_KEY, all at module scope).
# Loading this any later means those modules silently see empty strings
# regardless of what's in .env

load_dotenv(BASE_DIR / ".env")

_SRC = str(BASE_DIR / "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

_db = importlib.import_module("db_utils")
_gh = importlib.import_module("github_search")
_hibp = importlib.import_module("hibp_check")
_notifier = importlib.import_module("notifier")
_platform = importlib.import_module("platform_check")
_scheduler = importlib.import_module("scheduler")
_scraper = importlib.import_module("breach_scraper")
_secretcheck = importlib.import_module("secret_leak_check")
_validator = importlib.import_module("validator")
_init_db = importlib.import_module("init_db")
_tui = importlib.import_module("tui")


def _scan_and_render(identifier: str, check_id: int) -> None:
    """
    Run the multi-source breach scrape for an identifier and render
    whatever ends up in the local cache afterward.

    Cache-hit and cache-miss paths converge here on breach_cache as the
    single source of truth — a scrape just populates the cache, then
    this reads it back the same way a pure cache hit would.

    Args:
        identifier: The value being scanned.
        check_id: ID returned by db_utils.add_check() for this scan.
    """
    summary = _scraper.scrape_all(identifier)

    if summary.all_failed:
        _notifier.print_error(
            f"All {summary.sources_attempted} breach source(s) failed — "
            "check your internet connection."
        )
        return

    cached = _db.search_cache(identifier)
    for item in cached:
        _db.add_result(
            check_id,
            item["source"],
            item["breach_name"],
            raw_json=item.get("raw_json"),
        )
    _notifier.print_cache_results(identifier, cached)


def _check_email(email: str, offline: bool = False) -> None:
    """
    Run all checks for a single email address.

    Searches local cache first, then live APIs if no cache hit
    (unless offline, in which case a cache miss is reported as such).

    Args:
        email: Validated email address to check.
        offline: If True, never make network calls.
    """
    _notifier.print_section(f"Email — {email}")
    cached = _db.search_cache(email)
    if cached:
        _notifier.print_cache_results(email, cached)
        return
    if offline:
        _notifier.print_no_cache(email)
        return

    check_id = _db.add_check(email, "email")
    with _tui.BounceSpinner("Scanning breach sources..."):
        _scan_and_render(email, check_id)


def _check_username(username: str, offline: bool = False) -> None:
    """
    Run all checks for a single username.

    Args:
        username: Validated username to check.
        offline: If True, never make network calls.
    """
    _notifier.print_section(f"Username — {username}")
    cached = _db.search_cache(username)
    if cached:
        _notifier.print_cache_results(username, cached)
        return
    if offline:
        _notifier.print_no_cache(username)
        return

    check_id = _db.add_check(username, "username")
    with _tui.BounceSpinner("Scanning breach sources..."):
        _scan_and_render(username, check_id)

    with _tui.BounceSpinner("Checking GitHub exposure..."):
        gh_result = _gh.search_username(username)
    if gh_result and gh_result.get("total_count", 0) > 0:
        urls = _gh.get_exposed_urls(gh_result)
        _db.add_result(
            check_id,
            "GITHUB",
            f"{gh_result['total_count']} result(s)",
            raw_json=json.dumps(gh_result),
        )
        _notifier.print_github_results(username, gh_result["total_count"], urls)


def _check_phone(phone: str, offline: bool = False) -> None:
    """
    Run all checks for a single phone number.

    Prompts user for country code before validating.

    Args:
        phone: Raw phone string from .env.
        offline: If True, never make network calls.
    """
    country = (
        input(
            f"\n  Country code for {phone} " f"(e.g. US, GB, AU — see .env.example): "
        )
        .strip()
        .upper()
    )

    valid, result = _validator.validate_phone(phone, country)
    if not valid:
        _notifier.print_error(f"Phone validation failed: {result}")
        return

    _notifier.print_section(f"Phone — {result}")
    cached = _db.search_cache(result)
    if cached:
        _notifier.print_cache_results(result, cached)
        return
    if offline:
        _notifier.print_no_cache(result)
        return

    check_id = _db.add_check(result, "phone")
    with _tui.BounceSpinner("Scanning breach sources..."):
        _scan_and_render(result, check_id)


def _check_platform_usernames(offline: bool = False) -> None:
    """
    Prompt user to check platform-specific usernames at runtime.

    Args:
        offline: If True, delegate to _check_username in offline mode.
    """
    cats = _platform.list_platforms_by_category()
    print("\n  Available platform categories:")
    for category, labels in cats.items():
        print(f"    {category.capitalize()}: {', '.join(labels)}")

    answer = input("\n  Check a platform username? (y/n): ").strip().lower()
    if answer != "y":
        return

    platform_key = (
        input("  Platform (e.g. discord, steam, instagram): ").strip().lower()
    )

    if platform_key not in _platform.SUPPORTED_PLATFORMS:
        _notifier.print_error(f"Unsupported platform: {platform_key!r}")
        return

    label = _platform.get_platform_label(platform_key)
    username = input(f"  Your {label} username: ").strip()
    valid, result = _validator.validate_username(username)
    if not valid:
        _notifier.print_error(f"Username validation failed: {result}")
        return

    _check_username(result, offline=offline)


def _check_runtime_password(offline: bool = False) -> None:
    """
    Prompt for password check at runtime. Never stored.

    Passwords have no local cache to fall back on — offline mode
    skips this entirely rather than prompting for something it can't
    answer.

    Args:
        offline: If True, skip this check with a clear notice.
    """
    if offline:
        _notifier.print_offline_skip("Password exposure check")
        return

    answer = input("\n  Check a password for exposure? (y/n): ").strip().lower()
    if answer != "y":
        return

    password = getpass.getpass("  Password (hidden): ")
    valid, _ = _validator.validate_password(password)
    if not valid:
        _notifier.print_error("Password validation failed.")
        return

    _notifier.print_section("Password — k-anonymity check")
    with _tui.BounceSpinner("Checking password exposure..."):
        count = _hibp.check_password(password)

    if count == -1:
        _notifier.print_error("Password check could not complete.")
    elif count == 0:
        _notifier.print_clean("password")
    else:
        _notifier.print_breach_results(
            "password",
            [
                {
                    "breach_name": f"Seen {count:,} times in breach dumps",
                    "breach_date": "various",
                    "data_classes": "passwords",
                }
            ],
            "HIBP k-anonymity",
        )


def _advanced_github_token_search(label: str, token: str) -> None:
    """
    Optional, explicitly opt-in raw GitHub code search for a token.

    This sends the token as plaintext to GitHub's search API — it will
    appear in GitHub's query logs. Never triggered automatically; the
    caller must have already gotten a "y" to the hard warning below.

    Args:
        label: Human-readable name for the token.
        token: Validated token string to search for.
    """
    print()
    print("  Advanced mode (optional): raw GitHub code search")
    print("  This sends your token as PLAINTEXT to GitHub's search index")
    print("  and it will appear in GitHub's query logs. Only use this with")
    print("  a token you've already rotated/revoked — never a live credential.")
    answer = input("  Run raw GitHub search anyway? (y/n): ").strip().lower()
    if answer != "y":
        return

    with _tui.BounceSpinner(f"Scanning GitHub for {label} token..."):
        gh_result = _gh.search_token(token)
    if gh_result and gh_result.get("total_count", 0) > 0:
        urls = _gh.get_exposed_urls(gh_result)
        _notifier.print_github_results(label, gh_result["total_count"], urls)
    else:
        _notifier.print_clean(f"{label} token (raw GitHub search)")


def _check_runtime_token(offline: bool = False) -> None:
    """
    Prompt for token/key check at runtime. Never stored.

    Default check is hash-based via HasMySecretLeaked (ggshield) — only
    a truncated hash of the token ever leaves the machine. Raw GitHub
    literal-string search is available separately as an explicit,
    warned opt-in (see _advanced_github_token_search).

    Tokens have no local cache to fall back on — offline mode skips
    this entirely rather than prompting for something it can't answer.

    Args:
        offline: If True, skip this check with a clear notice.
    """
    if offline:
        _notifier.print_offline_skip("Token exposure check")
        return

    answer = input("\n  Check an API token or key? (y/n): ").strip().lower()
    if answer != "y":
        return

    label = input("  Token label (e.g. Discord, Steam, GitHub): ").strip()
    token = getpass.getpass(f"  {label} token (hidden): ")
    valid, result = _validator.validate_token(token, label)
    if not valid:
        _notifier.print_error(f"Token validation failed: {result}")
        return

    _notifier.print_section(f"Token — {label} hash-based leak check")
    if _secretcheck.is_available():
        with _tui.BounceSpinner("Checking HasMySecretLeaked..."):
            leak_result = _secretcheck.check_token(result)
        if leak_result is None:
            _notifier.print_error("HasMySecretLeaked check could not complete.")
        else:
            _notifier.print_hash_leak_results(label, leak_result["leaks"])
    else:
        _notifier.print_error(
            "ggshield not found — hash-based leak check unavailable. "
            "See docs/setup.md to install it (a few minutes, one-time)."
        )

    _advanced_github_token_search(label, result)


def _services_to_contact(emails: list, usernames: list, phones: list) -> list:
    """
    Determine which external services this run will actually contact,
    based on configured identifiers and which optional API keys are set.

    Only services that will genuinely be called are listed — sources
    silently skipped for lack of a key are left off rather than shown
    as a caveat, since the point is telling the user exactly who's
    about to receive their data.

    Args:
        emails: Configured email identifiers.
        usernames: Configured username identifiers.
        phones: Configured phone identifiers.

    Returns:
        Ordered list of service display names.
    """
    if not any([emails, usernames, phones]):
        return []

    services = ["LeakCheck", "BreachDirectory", "psbdmp.ws (paste site search)"]
    if emails:
        services.append("Emailrep.io")
    if os.getenv("HIBP_API_KEY"):
        services.append("HaveIBeenPwned")
    if os.getenv("OSINTLEAK_API_KEY"):
        services.append("OSINTLeak")
    if usernames:
        services.append("GitHub Code Search")
    return services


def _run_preflight_checks() -> None:
    """Run startup checks that don't depend on parsed identifiers yet."""
    if os.getenv("GITHUB_TOKEN"):
        _gh.check_token_scope()


def _resolve_identifiers(
    args: argparse.Namespace,
) -> Tuple[List[str], List[str], List[str]]:
    """
    Parse identifiers from .env and validate the total count against
    MAX_IDENTIFIERS, exiting with a clear message if either check fails.

    Args:
        args: Parsed CLI arguments (used for args.force).

    Returns:
        (emails, usernames, phones) tuple of parsed identifier lists.
    """
    emails = _validator.parse_csv_env(os.getenv("EMAILS_TO_CHECK", ""))
    usernames = _validator.parse_csv_env(os.getenv("USERNAMES_TO_CHECK", ""))
    phones = _validator.parse_csv_env(os.getenv("PHONES_TO_CHECK", ""))

    if not any([emails, usernames, phones]):
        _notifier.print_error(
            "No identifiers configured. "
            "Copy .env.example to .env and fill in your values."
        )
        sys.exit(1)

    total_identifiers = len(emails) + len(usernames) + len(phones)
    if total_identifiers > MAX_IDENTIFIERS and not args.force:
        _notifier.print_error(
            f"{total_identifiers} identifiers configured, which exceeds "
            f"the default safety limit of {MAX_IDENTIFIERS}. This could "
            "burn through free-tier API quota quickly or trigger a "
            "temporary rate-limit ban. Re-run with --force if this is "
            "intentional."
        )
        sys.exit(1)

    return emails, usernames, phones


def _confirm_scan(
    args: argparse.Namespace, emails: list, usernames: list, phones: list
) -> None:
    """
    Show the pre-scan consent notice and exit if the user declines.

    No-op in offline mode, since no network calls would be made anyway.

    Args:
        args: Parsed CLI arguments (used for args.offline).
        emails: Configured email identifiers.
        usernames: Configured username identifiers.
        phones: Configured phone identifiers.
    """
    if args.offline:
        return

    services = _services_to_contact(emails, usernames, phones)
    if not services:
        return

    _notifier.print_consent_notice(
        {"Emails": emails, "Usernames": usernames, "Phones": phones},
        services,
    )
    answer = input("\n  Continue? (y/n): ").strip().lower()
    if answer != "y":
        print("\n  Scan cancelled. No data was sent.\n")
        sys.exit(0)


def _run_identifier_scans(
    emails: list, usernames: list, phones: list, offline: bool
) -> None:
    """
    Run checks for every configured email, username, and phone number.

    Invalid entries are skipped with a warning rather than stopping
    the whole scan.

    Args:
        emails: Configured email identifiers.
        usernames: Configured username identifiers.
        phones: Configured phone identifiers.
        offline: If True, never make network calls.
    """
    for email in emails:
        valid, result = _validator.validate_email(email)
        if valid:
            _check_email(result, offline=offline)
        else:
            _notifier.print_error(f"Skipping invalid email: {result}")

    for username in usernames:
        valid, result = _validator.validate_username(username)
        if valid:
            _check_username(result, offline=offline)
        else:
            _notifier.print_error(f"Skipping invalid username: {result}")

    for phone in phones:
        _check_phone(phone, offline=offline)


def main() -> None:
    """Parse arguments and run the full scan."""
    parser = argparse.ArgumentParser(
        description="darkweb-exposure-toolkit — personal data exposure monitor"
    )
    network_mode = parser.add_mutually_exclusive_group()
    network_mode.add_argument(
        "--refresh",
        action="store_true",
        help="Force breach cache refresh before scanning",
    )
    network_mode.add_argument(
        "--offline",
        action="store_true",
        help=(
            "Make zero network calls — read only from the local cache. "
            "Identifiers with no cached entry are reported as such, "
            "never silently fetched live."
        ),
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help=(
            "Skip the identifier-count safety check. Use this only if "
            "you intentionally configured a large number of identifiers "
            f"(more than {MAX_IDENTIFIERS})."
        ),
    )
    args = parser.parse_args()

    _notifier.print_banner()
    _init_db.init_db()
    _run_preflight_checks()

    if args.refresh:
        print("  Running forced cache refresh...\n")
        _scheduler.run_refresh(force=True)

    if args.offline:
        print("  Offline mode — no network calls will be made.\n")

    emails, usernames, phones = _resolve_identifiers(args)
    _confirm_scan(args, emails, usernames, phones)
    _run_identifier_scans(emails, usernames, phones, args.offline)

    _check_platform_usernames(offline=args.offline)
    _check_runtime_password(offline=args.offline)
    _check_runtime_token(offline=args.offline)

    stats = _db.get_stats()
    _notifier.print_summary(stats)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  Scan interrupted. Partial results saved.\n")
        sys.exit(0)
    except Exception as exc:  # pylint: disable=broad-except
        print(f"\n  Unexpected error: {exc}\n")
        sys.exit(1)
