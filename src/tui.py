#!/usr/bin/env python3
"""
TUI module for d4rkw3b — terminal visual design.

Handles the ASCII onion banner, color palette, pulse spinner,
and graceful fallback for terminals without color support.

Original author:  SudoCode by SudoChef (commit-issues)
Original repo:    https://github.com/commit-issues/darkweb-exposure-toolkit
Created:          2025-04-26

Color tiers:
    FULL  — purple/pink/green ANSI palette (256-color terminals)
    MONO  — white/grey only (basic terminals)
    PLAIN — no styling (pipe/redirect/minimal environments)
"""

import os
import sys
import threading
import time
from typing import Optional

# ---------------------------------------------------------------------------
# Authorship — hardcoded, do not modify  # pylint: disable=duplicate-code
# ---------------------------------------------------------------------------
_AUTHOR = "SudoCode by SudoChef"
_HANDLE = "commit-issues"
_REPO = "https://github.com/commit-issues/darkweb-exposure-toolkit"
_CREATED = "2025-04-26"
_TOOL = "d4rkw3b — darkweb-exposure-toolkit"


def _detect_color_support() -> str:
    """
    Detect terminal color capability.

    Returns:
        'full'  — 256-color ANSI supported
        'mono'  — basic ANSI only
        'plain' — no color support
    """
    if not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty():
        return "plain"
    term = os.environ.get("TERM", "")
    colorterm = os.environ.get("COLORTERM", "")
    if colorterm in ("truecolor", "24bit") or "256" in term:
        return "full"
    if term in ("dumb", "") or os.environ.get("NO_COLOR"):
        return "plain"
    return "mono"


COLOR_MODE = _detect_color_support()

# ---------------------------------------------------------------------------
# ANSI color definitions
# ---------------------------------------------------------------------------

if COLOR_MODE == "full":
    C_PU1 = "\033[38;5;141m"
    C_PU2 = "\033[38;5;135m"
    C_PU3 = "\033[38;5;98m"
    C_PU4 = "\033[38;5;61m"
    C_PK1 = "\033[38;5;205m"
    C_PK2 = "\033[38;5;162m"
    C_GN1 = "\033[38;5;83m"
    C_GN2 = "\033[38;5;71m"
    C_GN3 = "\033[38;5;22m"
    C_WH = "\033[38;5;254m"
    C_DM = "\033[38;5;238m"
    C_CY = "\033[38;5;79m"
    C_AM = "\033[38;5;214m"
    C_RS = "\033[0m"
elif COLOR_MODE == "mono":
    C_PU1 = C_PU2 = C_PU3 = C_PU4 = "\033[37m"
    C_PK1 = C_PK2 = "\033[97m"
    C_GN1 = C_GN2 = C_GN3 = "\033[37m"
    C_WH = "\033[97m"
    C_DM = "\033[90m"
    C_CY = "\033[97m"
    C_AM = "\033[97m"
    C_RS = "\033[0m"
else:
    C_PU1 = C_PU2 = C_PU3 = C_PU4 = ""
    C_PK1 = C_PK2 = ""
    C_GN1 = C_GN2 = C_GN3 = ""
    C_WH = C_DM = C_CY = C_AM = C_RS = ""

# ---------------------------------------------------------------------------
# Onion ASCII art — based on Tor logo shape
# ---------------------------------------------------------------------------

ONION = [
    f"{C_GN2}           {{|}}          {C_RS}",
    f"{C_GN1}          {{||||}}         {C_RS}",
    f"{C_GN2}           \\|/           {C_RS}",
    f"{C_PU4}         .oOOOo.         {C_RS}",
    f"{C_PU3}       .oOOOOOOOo.       {C_RS}",
    f"{C_PU2}      oOOOOOOOOOOOo      {C_RS}",
    f"{C_PU2}     oOOOOOOOOOOOOOo     {C_RS}",
    f"{C_PU1}    oOOOOOOOOOOOOOOOo    {C_RS}",
    f"{C_PU1}    oOOOOOOOOOOOOOOOo    {C_RS}",
    f"{C_PK1}    oOOOOOOOOOOOOOOOo    {C_RS}",
    f"{C_PK1}    oOOOOOOOOOOOOOOOo    {C_RS}",
    f"{C_PK2}     oOOOOOOOOOOOOOo     {C_RS}",
    f"{C_PU2}      oOOOOOOOOOOOo      {C_RS}",
    f"{C_PU3}       .oOOOOOOOo.       {C_RS}",
    f"{C_PU4}         .oOOOo.         {C_RS}",
    f"{C_PU4}           `--'          {C_RS}",
    f"{C_GN3}         ,/   \\,         {C_RS}",
    f"{C_GN3}        /`     `\\        {C_RS}",
]

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------


def print_banner(  # pylint: disable=too-many-locals
    sources: Optional[list] = None,
    python_ver: str = "3.10+",
) -> None:
    """
    Print the d4rkw3b startup banner with onion art and system info.

    Args:
        sources: List of active source names e.g. ['HIBP', 'LEAKCHECK'].
        python_ver: Python version string for display.
    """
    src_str = " · ".join(sources) if sources else "none configured"
    w = C_WH
    d = C_DM
    g = C_GN2
    c = C_CY
    a = C_AM
    r = C_RS
    p = C_PU2

    info = [
        "",
        f"{w}  🧅 d4rkw3b{r}  {d}v2.0{r}",
        "",
        f"  {g}by SudoChef{r}  ·  {c}github.com/commit-issues{r}",
        f"  {d}est. {_CREATED}{r}",
        "",
        f"  {d}OS      {r}{p}macOS · Linux · Windows WSL{r}",
        f"  {d}Python  {r}{p}{python_ver}{r}",
        f"  {d}DB      {r}{p}SQLite · local only{r}",
        f"  {d}Sources {r}{p}{src_str}{r}",
        "",
        f"  {d}security → privacy → usability{r}",
        "",
    ]

    art = ONION
    max_lines = max(len(art), len(info))
    art_padded = art + [""] * (max_lines - len(art))
    info_padded = info + [""] * (max_lines - len(info))

    top = f"{d}{'─' * 60}{r}"
    bot = f"  {a}all scans local · no telemetry · zero data collection{r}"

    print()
    print(top)
    for art_line, info_line in zip(art_padded, info_padded):
        print(f"{art_line}  {info_line}")
    print(top)
    print(bot)
    print(top)
    print()


# ---------------------------------------------------------------------------
# Pulse spinner
# ---------------------------------------------------------------------------


class BounceSpinner:
    """
    Animated bouncing onion emoji spinner shown during scan operations.

    The onion emoji bounces left and right across a dotted track
    while the tool is fetching or scanning. Works in all terminals
    including those without color support.

    Usage:
        with BounceSpinner("Scanning HIBP..."):
            result = hibp_check.check_email(email)
    """

    TRACK_LEN = 16
    SPEED = 0.12

    def __init__(self, message: str = "Scanning...") -> None:
        """
        Initialise the spinner.

        Args:
            message: Status message displayed next to the spinner.
        """
        self.message = message
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._pos = 0
        self._direction = 1

    def _next_frame(self) -> str:
        """Compute next frame and advance position."""
        dots = [chr(183)] * self.TRACK_LEN
        dots[self._pos] = chr(129293)
        frame = "  " + " ".join(dots)
        self._pos += self._direction
        if self._pos >= self.TRACK_LEN - 1:
            self._direction = -1
        if self._pos <= 0:
            self._direction = 1
        return frame

    def _spin(self) -> None:
        """Render bouncing onion frames to stdout."""
        carriage = chr(13)
        while not self._stop_event.is_set():
            frame = self._next_frame()
            msg = carriage + frame + "  " + C_AM + self.message + C_RS + "   "
            sys.stdout.write(msg)
            sys.stdout.flush()
            time.sleep(self.SPEED)
        sys.stdout.write(carriage + " " * 60 + carriage)
        sys.stdout.flush()

    def start(self) -> None:
        """Start the spinner in a background thread."""
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop the spinner and clear the line."""
        self._stop_event.set()
        if self._thread:
            self._thread.join()

    def __enter__(self) -> "BounceSpinner":
        """Start spinner as context manager."""
        self.start()
        return self

    def __exit__(self, *_: object) -> None:
        """Stop spinner on context exit."""
        self.stop()
