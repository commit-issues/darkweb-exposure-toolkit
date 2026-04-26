#!/usr/bin/env python3
"""
darkweb-exposure-toolkit — Main entry point.

Runs all configured exposure checks against breach databases,
public code search, and the local breach cache. All results
are stored locally. Nothing is shared externally.

Usage:
    python3 src/run_all_checks.py           # full scan
    python3 src/run_all_checks.py --refresh # force cache refresh first
"""

import argparse
import importlib
import getpass
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Authorship — hardcoded, do not modify  # pylint: disable=duplicate-code
# ---------------------------------------------------------------------------
_AUTHOR = "SudoCode by SudoChef"
_HANDLE = "commit-issues"
_REPO = "https://github.com/commit-issues/darkweb-exposure-toolkit"
_CREATED = "2025-04-26"
_TOOL = "d4rkw3b — darkweb-exposure-toolkit"


BASE_DIR = Path(__file__).resolve().parent.parent

_SRC = str(BASE_DIR / "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

_db = importlib.import_module("db_utils")
_gh = importlib.import_module("github_search")
_hibp = importlib.import_module("hibp_check")
_notifier = importlib.import_module("notifier")
_platform = importlib.import_module("platform_check")
_scheduler = importlib.import_module("scheduler")
_validator = importlib.import_module("validator")
_init_db = importlib.import_module("init_db")
_tui = importlib.import_module("tui")


def _check_email(email: str) -> None:
    """
    Run all checks for a single email address.

    Searches local cache first, then live APIs if no cache hit.

    Args:
        email: Validated email address to check.
    """
    _notifier.print_section(f"Email — {email}")
    cached = _db.search_cache(email)
    if cached:
        _notifier.print_cache_results(email, cached)
        return

    check_id = _db.add_check(email, "email")
    with _tui.BounceSpinner("Scanning HIBP..."):
        breaches = _hibp.check_email(email)
    if breaches is not None:
        for b in breaches:
            _db.add_result(check_id, "HIBP", b.get("Name", "Unknown"), raw_json=str(b))
        _notifier.print_breach_results(email, breaches, "HIBP")
    else:
        _notifier.print_error("HIBP check could not complete.")


def _check_username(username: str) -> None:
    """
    Run all checks for a single username.

    Args:
        username: Validated username to check.
    """
    _notifier.print_section(f"Username — {username}")
    cached = _db.search_cache(username)
    if cached:
        _notifier.print_cache_results(username, cached)
        return

    check_id = _db.add_check(username, "username")
    with _tui.BounceSpinner("Scanning HIBP..."):
        breaches = _hibp.check_username(username)
    if breaches is not None:
        for b in breaches:
            _db.add_result(check_id, "HIBP", b.get("Name", "Unknown"), raw_json=str(b))
        _notifier.print_breach_results(username, breaches, "HIBP")

    with _tui.BounceSpinner("Checking GitHub exposure..."):
        gh_result = _gh.search_username(username)
    if gh_result and gh_result.get("total_count", 0) > 0:
        urls = _gh.get_exposed_urls(gh_result)
        _db.add_result(
            check_id,
            "GITHUB",
            f"{gh_result['total_count']} result(s)",
            raw_json=str(gh_result),
        )
        _notifier.print_github_results(username, gh_result["total_count"], urls)


def _check_phone(phone: str) -> None:
    """
    Run all checks for a single phone number.

    Prompts user for country code before validating.

    Args:
        phone: Raw phone string from .env.
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

    check_id = _db.add_check(result, "phone")
    with _tui.BounceSpinner("Scanning HIBP..."):
        breaches = _hibp.check_phone(result)
    if breaches is not None:
        for b in breaches:
            _db.add_result(check_id, "HIBP", b.get("Name", "Unknown"), raw_json=str(b))
        _notifier.print_breach_results(result, breaches, "HIBP")
    else:
        _notifier.print_error("Phone check could not complete.")


def _check_platform_usernames() -> None:
    """Prompt user to check platform-specific usernames at runtime."""
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

    _check_username(result)


def _check_runtime_password() -> None:
    """Prompt for password check at runtime. Never stored."""
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


def _check_runtime_token() -> None:
    """Prompt for token/key check at runtime. Never stored."""
    answer = input("\n  Check an API token or key? (y/n): ").strip().lower()
    if answer != "y":
        return

    label = input("  Token label (e.g. Discord, Steam, GitHub): ").strip()
    token = getpass.getpass(f"  {label} token (hidden): ")
    valid, result = _validator.validate_token(token, label)
    if not valid:
        _notifier.print_error(f"Token validation failed: {result}")
        return

    _notifier.print_section(f"Token — {label} GitHub exposure check")
    with _tui.BounceSpinner(f"Scanning GitHub for {label} token..."):
        gh_result = _gh.search_token(result)
    if gh_result and gh_result.get("total_count", 0) > 0:
        urls = _gh.get_exposed_urls(gh_result)
        _notifier.print_github_results(label, gh_result["total_count"], urls)
    else:
        _notifier.print_clean(f"{label} token")


def main() -> None:
    """Parse arguments and run the full scan."""
    load_dotenv()

    parser = argparse.ArgumentParser(
        description="darkweb-exposure-toolkit — personal data exposure monitor"
    )
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="Force breach cache refresh before scanning",
    )
    args = parser.parse_args()

    _notifier.print_banner()
    _init_db.init_db()

    if args.refresh:
        print("  Running forced cache refresh...\n")
        _scheduler.run_refresh(force=True)

    emails = _validator.parse_csv_env(os.getenv("EMAILS_TO_CHECK", ""))
    usernames = _validator.parse_csv_env(os.getenv("USERNAMES_TO_CHECK", ""))
    phones = _validator.parse_csv_env(os.getenv("PHONES_TO_CHECK", ""))

    if not any([emails, usernames, phones]):
        _notifier.print_error(
            "No identifiers configured. "
            "Copy .env.example to .env and fill in your values."
        )
        sys.exit(1)

    for email in emails:
        valid, result = _validator.validate_email(email)
        if valid:
            _check_email(result)
        else:
            _notifier.print_error(f"Skipping invalid email: {result}")

    for username in usernames:
        valid, result = _validator.validate_username(username)
        if valid:
            _check_username(result)
        else:
            _notifier.print_error(f"Skipping invalid username: {result}")

    for phone in phones:
        _check_phone(phone)

    _check_platform_usernames()
    _check_runtime_password()
    _check_runtime_token()

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
