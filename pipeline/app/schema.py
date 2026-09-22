"""
SQLite schema for the Loom medallion pipeline.

Layers:
  bronze_documents  — raw ingested text, verbatim
  silver_documents  — PII-scrubbed, normalised text
  gold_chunks       — chunked silver text with position metadata
  gold_embeddings   — sqlite-vec virtual table (384-dim float32 vectors)
"""

from __future__ import annotations

import os
import sqlite3

import sqlite_vec

DB_PATH: str = os.getenv("DB_PATH", "/data/loom.db")

_CREATE_BRONZE = """
CREATE TABLE IF NOT EXISTS bronze_documents (
    id          TEXT PRIMARY KEY,
    source      TEXT NOT NULL,
    content     TEXT NOT NULL,
    metadata    TEXT NOT NULL DEFAULT '{}',
    status      TEXT NOT NULL DEFAULT 'pending',
    ingested_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
)
"""
# status: pending | promoted | blocked

_CREATE_SILVER = """
CREATE TABLE IF NOT EXISTS silver_documents (
    id               TEXT PRIMARY KEY,
    bronze_id        TEXT NOT NULL REFERENCES bronze_documents(id),
    scrubbed_content TEXT NOT NULL,
    pii_entities     TEXT NOT NULL DEFAULT '[]',
    normalised_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
)
"""

_CREATE_GOLD_CHUNKS = """
CREATE TABLE IF NOT EXISTS gold_chunks (
    id          TEXT PRIMARY KEY,
    silver_id   TEXT NOT NULL REFERENCES silver_documents(id),
    chunk_index INTEGER NOT NULL,
    chunk_text  TEXT NOT NULL,
    embedded_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
)
"""

# sqlite-vec virtual table: 384 dimensions (all-MiniLM-L6-v2 output size)
_CREATE_GOLD_VEC = """
CREATE VIRTUAL TABLE IF NOT EXISTS gold_embeddings USING vec0(
    chunk_id  TEXT PRIMARY KEY,
    embedding float[384]
)
"""


def get_conn(db_path: str = DB_PATH) -> sqlite3.Connection:
    """Open a WAL-mode, foreign-key-enabled connection with sqlite-vec loaded."""
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    sqlite_vec.load(conn)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_schema(db_path: str = DB_PATH) -> None:
    """Create all tables if they do not already exist. Idempotent."""
    os.makedirs(os.path.dirname(db_path) if os.path.dirname(db_path) else ".", exist_ok=True)
    conn = get_conn(db_path)
    with conn:
        conn.execute(_CREATE_BRONZE)
        conn.execute(_CREATE_SILVER)
        conn.execute(_CREATE_GOLD_CHUNKS)
        conn.execute(_CREATE_GOLD_VEC)
    conn.close()
