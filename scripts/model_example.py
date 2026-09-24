#!/usr/bin/env python3
"""Make a bounded local model request; keep the bearer value out of argv/logs."""
import json
from pathlib import Path
import urllib.request

if __name__ == "__main__":
    root = Path(__file__).resolve().parents[1]
    token = (root / ".loom/client.token").read_text().strip()
    payload = {"model": "openai/gpt-4o-mini", "messages": [{"role": "user", "content": "Explain Go interfaces briefly."}], "max_tokens": 256}
    request = urllib.request.Request(
        "http://127.0.0.1:8080/v1/chat/completions",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "Authorization": "Bearer " + token},
    )
    with urllib.request.urlopen(request, timeout=35) as response:
        print(response.read().decode())
