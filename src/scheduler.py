#!/usr/bin/env python3
"""
24-hour refresh scheduler for breach intelligence cache.

Polls all configured sources once every 24 hours and updates
the local breach_cache table. Uses a lock file to prevent
duplicate runs if called multiple times within the window.

Usage:
    python3 src/scheduler.py              # run once, check if refresh needed
    python3 src/scheduler.py --force      # force refresh regardless of timing
"""

import argparse
import importlib
import os
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

# ---------------------------------------------------------------------------
# Authorship — hardcoded, do not modify  # pylint: disable=duplicate-code
# ---------------------------------------------------------------------------
_AUTHOR = "SudoCode by SudoChef"
_HANDLE = "commit-issues"
_REPO = "https://github.com/commit-issues/darkweb-exposure-toolkit"
_CREATED = "2025-04-26"
_TOOL = "d4rkw3b — darkweb-exposure-toolkit"


BASE_DIR = Path(__file__).resolve().parent.parent
LOCK_FILE = BASE_DIR / "data" / ".scheduler.lock"
LAST_RUN_FILE = BASE_DIR / "data" / ".last_refresh"
REFRESH_INTERVAL_HOURS = 24

if str(BASE_DIR / "src") not in sys.path:
    sys.path.insert(0, str(BASE_DIR / "src"))

_scraper = importlib.import_module("breach_scraper")
_validator = importlib.import_module("validator")


def _is_locked() -> bool:
    """
    Check if another scheduler instance is already running.

    Returns:
        True if lock file exists and process is still alive.
    """
    if not LOCK_FILE.exists():
        return False
    try:
        pid = int(LOCK_FILE.read_text(encoding="utf-8").strip())
        os.kill(pid, 0)
        return True
    except (ValueError, OSError):
        LOCK_FILE.unlink(missing_ok=True)
        return False


def _acquire_lock() -> None:
    """Write current PID to lock file."""
    LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    LOCK_FILE.write_text(str(os.getpid()), encoding="utf-8")


def _release_lock() -> None:
    """Remove lock file."""
    LOCK_FILE.unlink(missing_ok=True)


def _needs_refresh() -> bool:
    """
    Check if 24 hours have passed since the last refresh.

    Returns:
        True if refresh is due or has never run.
    """
    if not LAST_RUN_FILE.exists():
        return True
    try:
        last_run_str = LAST_RUN_FILE.read_text(encoding="utf-8").strip()
        last_run = datetime.fromisoformat(last_run_str)
        return datetime.now() - last_run > timedelta(hours=REFRESH_INTERVAL_HOURS)
    except (ValueError, OSError):
        return True


def _record_run() -> None:
    """Write current timestamp as last refresh time."""
    LAST_RUN_FILE.parent.mkdir(parents=True, exist_ok=True)
    LAST_RUN_FILE.write_text(datetime.now().isoformat(), encoding="utf-8")


def run_refresh(force: bool = False) -> None:
    """
    Run a full breach intelligence refresh across all identifiers.

    Reads EMAILS_TO_CHECK, USERNAMES_TO_CHECK, and PHONES_TO_CHECK
    from environment and scrapes all configured sources for each.

    Args:
        force: If True, skip the 24-hour interval check.
    """
    if not force and not _needs_refresh():
        print("Breach cache is up to date. Next refresh in less than 24 hours.")
        return

    if _is_locked():
        print("Scheduler is already running. Skipping.")
        return

    _acquire_lock()
    start = time.time()

    try:
        emails = _validator.parse_csv_env(os.getenv("EMAILS_TO_CHECK", ""))
        usernames = _validator.parse_csv_env(os.getenv("USERNAMES_TO_CHECK", ""))
        phones = _validator.parse_csv_env(os.getenv("PHONES_TO_CHECK", ""))
        identifiers = emails + usernames + phones

        if not identifiers:
            print("No identifiers configured. Add values to your .env file.")
            return

        print(f"Starting breach refresh for {len(identifiers)} identifier(s)...")
        total = 0

        for identifier in identifiers:
            print(f"  Scanning: {identifier}")
            count = _scraper.scrape_all(identifier)
            total += count
            print(f"  Found {count} new record(s)")

        elapsed = round(time.time() - start, 1)
        _record_run()
        print(f"\nRefresh complete — {total} total record(s) cached in {elapsed}s")

    finally:
        _release_lock()


def main() -> None:
    """Parse arguments and run the scheduler."""
    parser = argparse.ArgumentParser(
        description="darkweb-exposure-toolkit breach cache scheduler"
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force refresh regardless of last run time",
    )
    args = parser.parse_args()
    run_refresh(force=args.force)


if __name__ == "__main__":
    main()
