#!/usr/bin/env python3
"""
Hash-based token/API-key leak check via GitGuardian's HasMySecretLeaked
(HMSL) protocol.

The raw secret never leaves this machine — only a truncated, keyed hash
is sent by ggshield (k-anonymity, the same model HIBP uses for password
checks). This module shells out to the `ggshield` CLI rather than
importing it as a library: ggshield pins requests/python-dotenv versions
incompatible with this project's own pins, so it is deliberately NOT a
requirements.txt dependency. Install separately — see docs/setup.md.

The token is passed over stdin, never as a command-line argument, so it
never touches argv, the process list, or shell history.

Hardening notes (threat model: the ggshield binary itself, though
user-installed deliberately, is treated as a subprocess whose output
could be malformed, oversized, or unexpectedly shaped — whether from a
bug, a corrupted install, or a supply-chain compromise of the binary):
  - The resolved binary path is independently verified to exist as a
    file, on top of shutil.which()'s own executable check.
  - Subprocess output is capped before parsing, guarding against a
    compromised or malfunctioning binary flooding stdout in memory
    before the timeout is reached.
  - Parsed JSON is type-checked (leaks_count must be an int, leaks
    must be a list of dicts) before being returned — an unexpected
    shape is rejected rather than trusted.
  - Exception handling covers decode failures (non-UTF8 subprocess
    output), not just timeouts and OS-level errors.
"""

import json
import os
import shutil
import subprocess  # nosec B404
from typing import Dict, Optional

import notifier

# ---------------------------------------------------------------------------
# Authorship — hardcoded, do not modify  # pylint: disable=duplicate-code
# ---------------------------------------------------------------------------
_AUTHOR = "SudoCode by SudoChef"
_HANDLE = "commit-issues"
_REPO = "https://github.com/commit-issues/darkweb-exposure-toolkit"
_CREATED = "2025-04-26"
_TOOL = "d4rkw3b — darkweb-exposure-toolkit"

TIMEOUT = 30

# Generous for HMSL's actual output (a handful of leak records), but a
# firm ceiling against a compromised or malfunctioning ggshield binary
# producing unbounded output before the timeout is reached.
MAX_OUTPUT_BYTES = 2_000_000


def _resolved_path() -> Optional[str]:
    """
    Return the resolved absolute path to the ggshield binary, or None
    if it is not found on PATH or does not resolve to an actual file.

    shutil.which() already only returns executable matches, but the
    explicit os.path.isfile() check is a second, independent
    verification rather than relying solely on which()'s behavior.
    """
    path = shutil.which("ggshield")
    if path is None:
        return None
    if not os.path.isfile(path):
        return None
    return path


def is_available() -> bool:
    """Return True if the ggshield CLI is installed and on PATH."""
    return _resolved_path() is not None


def _extract_json(stdout: str) -> Optional[Dict]:
    """
    ggshield's --json output is preceded by human-readable progress
    lines on stdout (credits remaining, status, etc.) — scan from the
    end for the first line that parses as JSON rather than assuming
    a fixed line count.

    Args:
        stdout: Raw stdout from the ggshield subprocess.

    Returns:
        Parsed JSON dict, or None if no valid, correctly-shaped JSON
        line was found.
    """
    for line in reversed(stdout.strip().splitlines()):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            data = json.loads(line)
        except ValueError:
            continue
        if not isinstance(data, dict):
            continue
        return data
    return None


def _validate_leak_data(data: Dict) -> Optional[Dict]:
    """
    Type-check a parsed HMSL response before trusting it.

    Args:
        data: Dict already confirmed to be valid JSON by _extract_json.

    Returns:
        A normalized {'leaks_count': int, 'leaks': list} dict, or None
        if the response shape doesn't match what's expected — rejected
        rather than passed through with a wrong type that could crash
        a downstream caller (e.g. len() on a non-list 'leaks' value).
    """
    leaks_count = data.get("leaks_count", 0)
    leaks = data.get("leaks", [])

    if not isinstance(leaks_count, int):
        notifier.print_error("ggshield response had an unexpected leaks_count type.")
        return None
    if not isinstance(leaks, list):
        notifier.print_error("ggshield response had an unexpected leaks type.")
        return None
    if not all(isinstance(leak, dict) for leak in leaks):
        notifier.print_error("ggshield response contained a malformed leak entry.")
        return None

    return {"leaks_count": leaks_count, "leaks": leaks}


def check_token(token: str) -> Optional[Dict]:
    """
    Check a token/API key against HasMySecretLeaked via ggshield.

    Args:
        token: Validated token/key string to check.

    Returns:
        Dict with 'leaks_count' (int) and 'leaks' (list of match dicts —
        censored name, hash, occurrence count, source URL), or None on
        error (ggshield missing, network failure, unparseable or
        unexpectedly-shaped output).
    """
    ggshield_path = _resolved_path()
    if not ggshield_path:
        notifier.print_error(
            "ggshield is not installed — skipping HasMySecretLeaked check. "
            "See docs/setup.md for install instructions."
        )
        return None

    try:
        proc = subprocess.run(  # nosec B603
            [
                ggshield_path,
                "hmsl",
                "check",
                "--no-check-for-updates",
                "--json",
                "--naming-strategy",
                "none",
                "-",
            ],
            input=token,
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError, UnicodeDecodeError) as exc:
        notifier.print_error(f"HasMySecretLeaked check error: {exc}")
        return None

    if proc.returncode != 0:
        stderr_lines = proc.stderr.strip().splitlines() if proc.stderr else []
        detail = f" — {stderr_lines[-1]}" if stderr_lines else ""
        notifier.print_error(
            f"ggshield exited with an error (code {proc.returncode}){detail}"
        )
        return None

    if len(proc.stdout.encode("utf-8", errors="ignore")) > MAX_OUTPUT_BYTES:
        notifier.print_error(
            "ggshield produced an unexpectedly large amount of output — "
            "discarding it as a precaution."
        )
        return None

    data = _extract_json(proc.stdout)
    if data is None:
        notifier.print_error("Could not parse ggshield output.")
        return None

    return _validate_leak_data(data)
