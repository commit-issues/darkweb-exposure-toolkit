#!/usr/bin/env python3
"""
Initialize the local SQLite database.
Run once before your first scan to create all required tables.

Hardening note: the database file is created with restrictive
permissions (owner-only read/write, 0o600) ATOMICALLY on POSIX
systems, using os.open() with O_CREAT | O_EXCL rather than creating
the file with default permissions and restricting it afterward. The
previous create-then-chmod approach left a real, if brief, window
where the file existed on disk with default (typically world-
readable) permissions before being tightened — a classic
time-of-check-to-time-of-use gap. Atomic creation closes that window
entirely: the file never exists with anything but the intended
permissions, even for a moment.
"""

import os
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "exposure.db"

_AUTHOR = "SudoCode by SudoChef"
_HANDLE = "commit-issues"
_REPO = "https://github.com/commit-issues/darkweb-exposure-toolkit"
_CREATED = "2025-04-26"
_TOOL = "d4rkw3b — darkweb-exposure-toolkit"

CREATE_CHECKS = """
CREATE TABLE IF NOT EXISTS checks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    identifier  TEXT NOT NULL,
    check_type  TEXT NOT NULL,
    note        TEXT
);
"""

CREATE_RESULTS = """
CREATE TABLE IF NOT EXISTS results (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    check_id   INTEGER NOT NULL,
    source     TEXT NOT NULL,
    summary    TEXT,
    url        TEXT,
    raw_json   TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (check_id) REFERENCES checks(id)
);
"""

CREATE_BREACH_CACHE = """
CREATE TABLE IF NOT EXISTS breach_cache (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    identifier   TEXT NOT NULL,
    source       TEXT NOT NULL,
    breach_name  TEXT NOT NULL,
    data_classes TEXT,
    breach_date  TEXT,
    raw_json     TEXT,
    cached_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(identifier, source, breach_name)
);
"""

CREATE_CACHE_INDEX = """
CREATE INDEX IF NOT EXISTS idx_breach_cache_identifier
ON breach_cache (identifier);
"""

CREATE_WATERMARK = """
CREATE TABLE IF NOT EXISTS watermark (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    tool       TEXT NOT NULL,
    author     TEXT NOT NULL,
    handle     TEXT NOT NULL,
    repo       TEXT NOT NULL,
    created    TEXT NOT NULL,
    db_init_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""


def _create_file_atomically_with_restricted_permissions() -> None:
    """
    Create the database file with 0o600 permissions in a single
    atomic operation, if it doesn't already exist.

    Uses O_CREAT | O_EXCL so file creation and permission-setting
    happen as one indivisible OS-level step — there is no window
    where the file exists with any other permissions, unlike a
    separate create-then-chmod sequence. If the file already exists
    (from a prior run), this is a safe no-op; POSIX only, matching
    the scope of the original chmod-based approach.
    """
    if os.name != "posix":
        return
    try:
        fd = os.open(DB_PATH, os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
    except FileExistsError:
        pass


def get_connection() -> sqlite3.Connection:
    """Return a connection to the local SQLite database."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    _create_file_atomically_with_restricted_permissions()
    return sqlite3.connect(DB_PATH)


def _write_watermark(cur: sqlite3.Cursor) -> None:
    """
    Write authorship watermark to the database.

    Uses INSERT OR IGNORE so it only writes once — on first init.
    The watermark is permanent and survives all future runs.

    Args:
        cur: Active database cursor.
    """
    cur.execute(
        "INSERT OR IGNORE INTO watermark "
        "(id, tool, author, handle, repo, created) "
        "VALUES (1, ?, ?, ?, ?, ?)",
        (_TOOL, _AUTHOR, _HANDLE, _REPO, _CREATED),
    )


def _secure_permissions() -> None:
    """
    Restrict data/exposure.db to owner-only read/write (chmod 600).

    Kept as a defense-in-depth backstop even though get_connection()
    now creates new files with correct permissions atomically — this
    still matters for an existing database file from before this fix
    (or from any other code path that might touch the file), so a
    previously world-readable file gets corrected on the next run.

    POSIX only — Windows has no equivalent POSIX permission bit; rely
    on disk encryption / account separation there instead.
    """
    if os.name == "posix":
        os.chmod(DB_PATH, 0o600)


def init_db() -> None:
    """Create all tables and indexes if they do not already exist."""
    conn = get_connection()
    cur = conn.cursor()
    cur.executescript(
        CREATE_CHECKS
        + CREATE_RESULTS
        + CREATE_BREACH_CACHE
        + CREATE_CACHE_INDEX
        + CREATE_WATERMARK
    )
    _write_watermark(cur)
    conn.commit()
    conn.close()
    _secure_permissions()
    print(f"Database ready at: {DB_PATH}")


if __name__ == "__main__":
    init_db()
