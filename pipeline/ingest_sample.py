#!/usr/bin/env python3
"""
Ingest sample documents into the Loom pipeline service.

Usage:
    python3 pipeline/ingest_sample.py [--url http://localhost:8181] [--wait]

Options:
    --url URL   Pipeline base URL (default: http://localhost:8181)
    --wait      Poll /status for each document until gold promotion completes
    --file PATH JSONL file to ingest (default: pipeline/sample-data/loom-docs.jsonl)
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

DEFAULT_URL = "http://localhost:8181"
DEFAULT_FILE = Path(__file__).parent / "sample-data" / "loom-docs.jsonl"
POLL_TIMEOUT = 60  # seconds


def post_json(url: str, payload: dict) -> dict:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


def get_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=10) as resp:
        return json.loads(resp.read())


def wait_for_health(base_url: str, retries: int = 20, delay: float = 2.0) -> None:
    print(f"Waiting for pipeline service at {base_url} ...", end="", flush=True)
    for _ in range(retries):
        try:
            data = get_json(f"{base_url}/health")
            if data.get("status") == "healthy":
                print(" ready.")
                return
        except (urllib.error.URLError, OSError):
            pass
        print(".", end="", flush=True)
        time.sleep(delay)
    print()
    print("ERROR: Pipeline service did not become healthy in time.", file=sys.stderr)
    sys.exit(1)


def ingest_file(base_url: str, jsonl_path: Path, wait: bool) -> None:
    lines = [ln.strip() for ln in jsonl_path.read_text().splitlines() if ln.strip()]
    doc_ids: list[str] = []

    print(f"\nIngesting {len(lines)} documents from {jsonl_path.name}...")
    for i, line in enumerate(lines, 1):
        doc = json.loads(line)
        resp = post_json(f"{base_url}/ingest", doc)
        doc_id = resp["doc_id"]
        doc_ids.append(doc_id)
        print(f"  [{i:02d}/{len(lines)}] queued  {doc_id[:8]}…  source={doc['source']!r}")

    if not wait:
        print(f"\nDone. {len(doc_ids)} documents queued.")
        print("Promotion (silver+gold) runs in the background.")
        print(f"Check progress: GET {base_url}/medallion/stats")
        return

    print(f"\nWaiting for promotion (timeout {POLL_TIMEOUT}s)...")
    deadline = time.monotonic() + POLL_TIMEOUT
    pending = set(doc_ids)

    while pending and time.monotonic() < deadline:
        time.sleep(2)
        still_pending = set()
        for doc_id in pending:
            try:
                st = get_json(f"{base_url}/status/{doc_id}")
                if st["bronze_status"] in ("promoted", "blocked"):
                    status_icon = "✓" if st["bronze_status"] == "promoted" else "✗"
                    print(
                        f"  {status_icon} {doc_id[:8]}…  "
                        f"silver={st['silver_records']}  "
                        f"chunks={st['gold_chunks']}"
                    )
                else:
                    still_pending.add(doc_id)
            except (urllib.error.URLError, OSError):
                still_pending.add(doc_id)
        pending = still_pending

    stats = get_json(f"{base_url}/medallion/stats")
    print(f"\nMedallion stats: {json.dumps(stats, indent=2)}")
    print(f"\nReady! Try a search:")
    print(f'  curl "{base_url}/search?q=how+does+the+guardrail+proxy+work&k=3"')
    print(f"\nOr a full RAG query:")
    print(
        f'  curl -X POST {base_url}/rag \\\n'
        f'    -H \'Content-Type: application/json\' \\\n'
        f'    -d \'{{"query": "How does the RAG pipeline protect LLM responses?", "k": 4}}\''
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Ingest sample data into the Loom pipeline")
    parser.add_argument("--url", default=DEFAULT_URL, help="Pipeline base URL")
    parser.add_argument("--file", type=Path, default=DEFAULT_FILE, help="JSONL file to ingest")
    parser.add_argument("--wait", action="store_true", help="Wait for gold promotion to complete")
    args = parser.parse_args()

    wait_for_health(args.url)
    ingest_file(args.url, args.file, wait=args.wait)


if __name__ == "__main__":
    main()
