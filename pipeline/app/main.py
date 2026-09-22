"""
Loom Ingestion Pipeline — FastAPI application.

Endpoints:
  GET  /health              Service health
  GET  /medallion/stats     Row counts per medallion layer
  POST /ingest              Submit a raw document (returns immediately, async promotion)
  GET  /status/{doc_id}     Check promotion status
  GET  /search              Vector similarity search over the gold layer
  POST /rag                 Full RAG: retrieve → augment → generate via agentgateway
"""

from __future__ import annotations

import sqlite3
from contextlib import asynccontextmanager
from typing import Any

from fastapi import BackgroundTasks, FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from .embeddings import _load_model
from .medallion import ingest_bronze, promote_gold, promote_silver
from .rag import generate, retrieve
from .schema import DB_PATH, get_conn, init_schema

# ── Application state ──────────────────────────────────────────────────────────

_conn: sqlite3.Connection | None = None


def _db() -> sqlite3.Connection:
    """Return the shared database connection (asserted initialised)."""
    assert _conn is not None, "Database not initialised"
    return _conn


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Initialise schema, open the shared connection, and pre-warm embeddings."""
    global _conn
    init_schema(DB_PATH)
    _conn = get_conn(DB_PATH)
    _load_model()  # pre-warm; avoids first-request latency spike
    yield
    if _conn:
        _conn.close()
        _conn = None


app = FastAPI(
    title="Loom Ingestion Pipeline",
    description=(
        "Secure data ingestion with medallion architecture "
        "(Bronze → Silver → Gold) and RAG via agentgateway."
    ),
    version="1.0.0",
    lifespan=lifespan,
)


# ── Background task ────────────────────────────────────────────────────────────

async def _run_promotion(doc_id: str) -> None:
    """Promote a bronze document through silver and gold asynchronously."""
    silver_id = await promote_silver(_db(), doc_id)
    if silver_id:
        await promote_gold(_db(), silver_id)


# ── Request / response models ──────────────────────────────────────────────────

class IngestRequest(BaseModel):
    source: str = Field(..., description="Identifier for the originating data source")
    content: str = Field(..., min_length=1, description="Raw document text to ingest")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Arbitrary metadata")


class IngestResponse(BaseModel):
    doc_id: str
    status: str = "pending"
    message: str = "Document queued. Use GET /status/{doc_id} to track promotion."


class RAGRequest(BaseModel):
    query: str = Field(..., min_length=1, description="Natural-language question")
    k: int = Field(default=5, ge=1, le=20, description="Number of context chunks to retrieve")
    model: str = Field(default="openai/gpt-4o-mini", description="LLM model identifier")


class RAGResponse(BaseModel):
    query: str
    answer: str
    sources: list[dict]
    chunks_used: int


# ── Endpoints ──────────────────────────────────────────────────────────────────

@app.get("/health", tags=["ops"])
async def health():
    return {"status": "healthy", "service": "loom-pipeline"}


@app.get("/medallion/stats", tags=["ops"])
async def medallion_stats():
    """Return row counts for each medallion layer."""
    db = _db()
    bronze = db.execute("SELECT COUNT(*) FROM bronze_documents").fetchone()[0]
    blocked = db.execute(
        "SELECT COUNT(*) FROM bronze_documents WHERE status = 'blocked'"
    ).fetchone()[0]
    silver = db.execute("SELECT COUNT(*) FROM silver_documents").fetchone()[0]
    chunks = db.execute("SELECT COUNT(*) FROM gold_chunks").fetchone()[0]
    return {
        "bronze": bronze,
        "silver": silver,
        "gold_chunks": chunks,
        "blocked": blocked,
    }


@app.post("/ingest", response_model=IngestResponse, status_code=202, tags=["ingestion"])
async def ingest(req: IngestRequest, background_tasks: BackgroundTasks):
    """
    Ingest a raw document into the bronze layer.
    Silver (PII scrub + validation) and gold (chunk + embed) promotion
    happen asynchronously in the background.
    """
    doc_id = await ingest_bronze(_db(), req.source, req.content, req.metadata)
    background_tasks.add_task(_run_promotion, doc_id)
    return IngestResponse(doc_id=doc_id)


@app.get("/status/{doc_id}", tags=["ingestion"])
async def status(doc_id: str):
    """Return the promotion status and layer counts for a document."""
    db = _db()
    row = db.execute(
        "SELECT status FROM bronze_documents WHERE id = ?", (doc_id,)
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Document not found")

    silver_count = db.execute(
        "SELECT COUNT(*) FROM silver_documents WHERE bronze_id = ?", (doc_id,)
    ).fetchone()[0]

    gold_count = db.execute(
        """
        SELECT COUNT(*) FROM gold_chunks gc
        JOIN silver_documents sd ON sd.id = gc.silver_id
        WHERE sd.bronze_id = ?
        """,
        (doc_id,),
    ).fetchone()[0]

    return {
        "doc_id": doc_id,
        "bronze_status": row["status"],
        "silver_records": silver_count,
        "gold_chunks": gold_count,
    }


@app.get("/search", tags=["retrieval"])
async def search(
    q: str = Query(..., description="Search query"),
    k: int = Query(default=5, ge=1, le=20, description="Number of results"),
):
    """Vector similarity search over the gold layer."""
    chunks = retrieve(_db(), q, k=k)
    return {"query": q, "results": chunks, "count": len(chunks)}


@app.post("/rag", response_model=RAGResponse, tags=["retrieval"])
async def rag(req: RAGRequest):
    """
    Full RAG pipeline:
      1. Embed the query.
      2. Retrieve top-k chunks from the gold layer (sqlite-vec KNN).
      3. Build an augmented prompt.
      4. Send to agentgateway → OpenRouter LLM.
         (agentgateway guardrail webhooks fire automatically on both
          the outgoing prompt and the incoming response.)
      5. Return the grounded answer.
    """
    chunks = retrieve(_db(), req.query, k=req.k)
    if not chunks:
        raise HTTPException(
            status_code=404,
            detail="No relevant context found. Ingest documents first via POST /ingest.",
        )
    answer = await generate(req.query, chunks, model=req.model)
    sources = [
        {"text": c["text"][:120] + ("…" if len(c["text"]) > 120 else ""), "score": c["score"]}
        for c in chunks
    ]
    return RAGResponse(
        query=req.query,
        answer=answer,
        sources=sources,
        chunks_used=len(chunks),
    )
