# ==============================================================================
# Loom Ingestion Pipeline — Dockerfile
# ==============================================================================
# Single-stage Python 3.12 slim image.
# The sentence-transformers model (all-MiniLM-L6-v2, ~90 MB) is downloaded
# during the image build so container starts are instant.
# ==============================================================================

FROM python:3.12-slim

WORKDIR /app

# System dependencies: curl for healthcheck, git for sentence-transformers
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl git \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Sanity-check SQLite version (sqlite-vec requires ≥ 3.41)
RUN python - <<'EOF'
import sqlite3, sys
ver = tuple(int(x) for x in sqlite3.sqlite_version.split("."))
assert ver >= (3, 41, 0), f"SQLite {sqlite3.sqlite_version} is too old; need ≥ 3.41"
print(f"SQLite version OK: {sqlite3.sqlite_version}")
EOF

# Pre-download the embedding model into /models during build.
# This makes the layer ~350 MB but avoids slow first-start downloads.
RUN python -c "\
from sentence_transformers import SentenceTransformer; \
SentenceTransformer('all-MiniLM-L6-v2', cache_folder='/models'); \
print('Embedding model cached.')"

# Copy application source
COPY app/ ./app/

EXPOSE 8181

HEALTHCHECK --interval=5s --timeout=3s --retries=15 --start-period=20s \
    CMD curl -fsS http://localhost:8181/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8181"]
