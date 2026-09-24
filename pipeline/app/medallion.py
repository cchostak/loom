"""
Medallion architecture transforms: Bronze → Silver → Gold.

  Bronze  raw, verbatim ingestion
  Silver  guardrail-validated, PII-scrubbed, normalised
  Gold    chunked, embedded, indexed for vector search
"""

from __future__ import annotations

import json
import re
import sqlite3
import uuid
from dataclasses import dataclass

import sqlite_vec

from .embeddings import embed_batch
from .guardrail import ContentBlockedError, GuardrailError, scrub_pii, validate

# ── Chunking parameters ────────────────────────────────────────────────────────
_CHUNK_SIZE = 512    # characters
_CHUNK_OVERLAP = 64  # characters of overlap between consecutive chunks


# ── Helpers ────────────────────────────────────────────────────────────────────

def _chunk(text: str) -> list[str]:
    """Fixed-size character-level chunking with overlap."""
    if len(text) <= _CHUNK_SIZE:
        return [text.strip()] if text.strip() else []

    step = _CHUNK_SIZE - _CHUNK_OVERLAP
    chunks: list[str] = []
    for start in range(0, len(text), step):
        segment = text[start: start + _CHUNK_SIZE].strip()
        if segment:
            chunks.append(segment)
    return chunks


def _normalise(text: str) -> str:
    """Light normalisation: consistent line endings, collapsed whitespace."""
    text = re.sub(r"\r\n|\r", "\n", text)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


# ── Bronze ─────────────────────────────────────────────────────────────────────

async def ingest_bronze(
    conn: sqlite3.Connection,
    source: str,
    content: str,
    metadata: dict,
) -> str:
    """Write raw document to the bronze layer. Returns doc_id."""
    doc_id = str(uuid.uuid4())
    with conn:
        conn.execute(
            "INSERT INTO bronze_documents (id, source, content, metadata)"
            " VALUES (?, ?, ?, ?)",
            (doc_id, source, content, json.dumps(metadata)),
        )
    return doc_id


# ── Silver ─────────────────────────────────────────────────────────────────────

async def promote_silver(conn: sqlite3.Connection, doc_id: str) -> str | None:
    """
    Bronze → Silver promotion.

    Steps:
      1. Fetch bronze record.
      2. Validate against guardrail-proxy forbidden patterns.
      3. Scrub PII via presidio-analyzer.
      4. Normalise whitespace and encoding.
      5. Write silver record; update bronze status.

    Returns silver_id on success, None if the guardrail blocked the content.
    Raises GuardrailError if the guardrail proxy is unreachable.
    """
    row = conn.execute(
        "SELECT content FROM bronze_documents WHERE id = ?", (doc_id,)
    ).fetchone()
    if not row:
        raise ValueError(f"Bronze document {doc_id!r} not found")

    content: str = row["content"]

    # 1. Guardrail errors leave the document pending; never promote unchecked.
    try:
        await validate(content)
    except ContentBlockedError:
        with conn:
            conn.execute(
                "UPDATE bronze_documents SET status = 'blocked' WHERE id = ?",
                (doc_id,),
            )
        return None

    # 2. PII scrubbing (fail closed)
    scrubbed, entities = await scrub_pii(content)

    # 3. Normalise
    normalised = _normalise(scrubbed)

    silver_id = str(uuid.uuid4())
    with conn:
        conn.execute(
            "INSERT INTO silver_documents (id, bronze_id, scrubbed_content, pii_entities)"
            " VALUES (?, ?, ?, ?)",
            (silver_id, doc_id, normalised, json.dumps(entities)),
        )
        conn.execute(
            "UPDATE bronze_documents SET status = 'promoted' WHERE id = ?",
            (doc_id,),
        )
    return silver_id


# ── Gold ───────────────────────────────────────────────────────────────────────

async def promote_gold(conn: sqlite3.Connection, silver_id: str) -> list[str]:
    """
    Silver → Gold promotion.

    Steps:
      1. Fetch silver record.
      2. Chunk the scrubbed text.
      3. Batch-embed all chunks.
      4. Write gold_chunks rows and gold_embeddings vec0 rows.

    Returns list of chunk_ids written.
    """
    row = conn.execute(
        "SELECT scrubbed_content FROM silver_documents WHERE id = ?", (silver_id,)
    ).fetchone()
    if not row:
        raise ValueError(f"Silver document {silver_id!r} not found")

    chunks = _chunk(row["scrubbed_content"])
    if not chunks:
        return []

    vectors = embed_batch(chunks)

    chunk_ids: list[str] = []
    with conn:
        for idx, (chunk_text, vector) in enumerate(zip(chunks, vectors)):
            chunk_id = str(uuid.uuid4())
            conn.execute(
                "INSERT INTO gold_chunks (id, silver_id, chunk_index, chunk_text)"
                " VALUES (?, ?, ?, ?)",
                (chunk_id, silver_id, idx, chunk_text),
            )
            conn.execute(
                "INSERT INTO gold_embeddings (chunk_id, embedding) VALUES (?, ?)",
                (chunk_id, sqlite_vec.serialize_float32(vector)),
            )
            chunk_ids.append(chunk_id)

    return chunk_ids
