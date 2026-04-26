#!/usr/bin/env python3
"""
Integrity verification for d4rkw3b.

Checks tui.py has not been tampered with and that authorship
metadata is intact. Warns on startup if anything looks wrong.

Original author:  SudoCode by SudoChef (commit-issues)
Original repo:    https://github.com/commit-issues/darkweb-exposure-toolkit
Created:          2025-04-26
"""

import hashlib
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Authorship constants — hardcoded, do not modify
# ---------------------------------------------------------------------------

AUTHOR = "SudoCode by SudoChef"
HANDLE = "commit-issues"
REPO = "https://github.com/commit-issues/darkweb-exposure-toolkit"
CREATED = "2025-04-26"
TOOL = "d4rkw3b — darkweb-exposure-toolkit"

WATERMARK = f"{TOOL} | {AUTHOR} ({HANDLE}) | {REPO} | est. {CREATED}"

BASE_DIR = Path(__file__).resolve().parent.parent
TUI_PATH = BASE_DIR / "src" / "tui.py"
HASH_FILE = BASE_DIR / "data" / ".tui_hash"


def _sha256(path: Path) -> str:
    """
    Compute SHA-256 hash of a file.

    Args:
        path: Path to the file to hash.

    Returns:
        Hex digest string.
    """
    sha = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            sha.update(chunk)
    return sha.hexdigest()


def write_hash() -> None:
    """
    Write current tui.py hash to data/.tui_hash.
    Run this after any intentional change to tui.py.
    """
    HASH_FILE.parent.mkdir(parents=True, exist_ok=True)
    current = _sha256(TUI_PATH)
    HASH_FILE.write_text(current, encoding="utf-8")
    print(f"Hash written: {current[:16]}...")
    print(f"Stored at:   {HASH_FILE}")


def verify_tui() -> bool:
    """
    Verify tui.py has not been modified since last hash write.

    Returns:
        True if hash matches or no baseline exists yet.
        False if tampering detected.
    """
    if not TUI_PATH.exists():
        print(
            f"  WARNING: tui.py not found at {TUI_PATH}",
            file=sys.stderr,
        )
        return False

    if not HASH_FILE.exists():
        return True

    stored = HASH_FILE.read_text(encoding="utf-8").strip()
    current = _sha256(TUI_PATH)

    if stored != current:
        print(
            "\n  WARNING: tui.py has been modified since last verification.",
            file=sys.stderr,
        )
        print(
            "  If this was intentional, run: python3 src/verify.py --rehash",
            file=sys.stderr,
        )
        return False

    return True


def print_authorship() -> None:
    """Print authorship watermark to stdout."""
    print(WATERMARK)


if __name__ == "__main__":
    if "--rehash" in sys.argv:
        write_hash()
    elif "--watermark" in sys.argv:
        print_authorship()
    else:
        passed = verify_tui()  # pylint: disable=invalid-name
        if passed:
            print("Integrity check passed.")
        else:
            print("Integrity check FAILED.", file=sys.stderr)
            sys.exit(1)
