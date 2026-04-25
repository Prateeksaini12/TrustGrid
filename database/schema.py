"""
database/schema.py
------------------
Database connection helper and schema initialisation.
All raw SQL lives here - routes never write SQL directly.
"""

import sqlite3

from config import DB_PATH


def get_db() -> sqlite3.Connection:
    """Open and return a SQLite connection with dict-like row access."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """
    Create all tables if they do not already exist.
    Safe to call on every startup - uses IF NOT EXISTS.
    """
    conn = get_db()
    c = conn.cursor()

    c.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            node_id  TEXT    UNIQUE NOT NULL,
            key_hash TEXT    NOT NULL,
            company  TEXT    NOT NULL,
            ip       TEXT,
            created  TEXT    DEFAULT (datetime('now'))
        )
        """
    )

    c.execute(
        """
        CREATE TABLE IF NOT EXISTS transactions (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            company       TEXT    NOT NULL,
            node_id       TEXT    NOT NULL,
            fe_ciphertext TEXT,
            fraud_score   INTEGER NOT NULL DEFAULT 0,
            is_fraud      INTEGER NOT NULL,
            created       TEXT    DEFAULT (datetime('now'))
        )
        """
    )
    _ensure_column(c, "transactions", "fe_ciphertext", "TEXT")
    _ensure_column(c, "transactions", "fraud_score", "INTEGER NOT NULL DEFAULT 0")

    c.execute(
        """
        CREATE TABLE IF NOT EXISTS fraud_outcomes (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            participating_nodes TEXT    NOT NULL,
            total_records       INTEGER,
            total_fraud         INTEGER,
            node_count          INTEGER,
            decision            TEXT,
            created             TEXT    DEFAULT (datetime('now'))
        )
        """
    )

    conn.commit()
    conn.close()


def _ensure_column(cursor: sqlite3.Cursor, table: str, column: str, definition: str) -> None:
    """Add a missing column to an existing SQLite table."""
    existing = {
        row["name"] if isinstance(row, sqlite3.Row) else row[1]
        for row in cursor.execute(f"PRAGMA table_info({table})").fetchall()
    }
    if column not in existing:
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
