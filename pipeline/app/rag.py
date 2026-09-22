"""
Retrieval-Augmented Generation pipeline.

retrieve() performs vector-similarity search over the gold layer using sqlite-vec.
generate() sends the augmented prompt to agentgateway, which automatically
applies the existing guardrail webhook on both the request and the response.
"""

from __future__ import annotations

import json
import os
import sqlite3

import httpx
import sqlite_vec

from .embeddings import embed

AGENTGATEWAY_URL: str = os.getenv("AGENTGATEWAY_URL", "http://agentgateway:8080/v1")
DEFAULT_MODEL: str = os.getenv("DEFAULT_RAG_MODEL", "openai/gpt-4o-mini")

_SYSTEM_PROMPT = (
    "You are a helpful assistant. Answer the user's question using ONLY the "
    "provided context excerpts. If the context does not contain enough "
    "information to answer confidently, say so. Do not invent facts."
)


def retrieve(
    conn: sqlite3.Connection,
    query: str,
    k: int = 5,
) -> list[dict]:
    """
    Embed the query and perform KNN vector search over gold_embeddings.
    Returns a list of dicts with keys: text, silver_id, score (distance).
    """
    query_vec = sqlite_vec.serialize_float32(embed(query))

    rows = conn.execute(
        """
        SELECT
            gc.chunk_text,
            gc.silver_id,
            ge.distance
        FROM gold_embeddings ge
        JOIN gold_chunks gc ON gc.id = ge.chunk_id
        WHERE ge.embedding MATCH ?
          AND k = ?
        ORDER BY ge.distance
        """,
        (query_vec, k),
    ).fetchall()

    return [
        {
            "text": row["chunk_text"],
            "silver_id": row["silver_id"],
            "score": row["distance"],
        }
        for row in rows
    ]


def _build_augmented_prompt(query: str, chunks: list[dict]) -> str:
    """Construct the context-augmented prompt sent to the LLM."""
    parts = [f"[{i + 1}] {chunk['text']}" for i, chunk in enumerate(chunks)]
    context = "\n\n".join(parts)
    return f"Context:\n{context}\n\nQuestion: {query}"


async def generate(
    query: str,
    chunks: list[dict],
    model: str = DEFAULT_MODEL,
) -> str:
    """
    Send the augmented prompt to agentgateway and return the LLM answer.

    The agentgateway guardrail webhook fires automatically on both the
    outgoing request (augmented prompt + context) and the incoming response
    (LLM answer). No extra guardrail instrumentation is needed here.
    """
    augmented = _build_augmented_prompt(query, chunks)
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": augmented},
        ],
    }
    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.post(
            f"{AGENTGATEWAY_URL}/chat/completions",
            json=payload,
            headers={"Content-Type": "application/json"},
        )
        resp.raise_for_status()

    data = resp.json()
    return data["choices"][0]["message"]["content"]
