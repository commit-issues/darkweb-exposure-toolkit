#!/usr/bin/env python3
"""
Initialize the local SQLite database.
Run once before your first scan to create all required tables.
"""

import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "exposure.db"

# ---------------------------------------------------------------------------
# Authorship — hardcoded, do not modify  # pylint: disable=duplicate-code
# ---------------------------------------------------------------------------
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


def get_connection() -> sqlite3.Connection:
    """Return a connection to the local SQLite database."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
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
    print(f"Database ready at: {DB_PATH}")


if __name__ == "__main__":
    init_db()
