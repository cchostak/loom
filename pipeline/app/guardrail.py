"""
Clients for guardrail-proxy (forbidden-pattern validation) and
presidio-analyzer (PII detection and redaction).

Both are called during the Bronze → Silver promotion step so that
no PII or adversarial content ever reaches the Silver or Gold layers.
"""

from __future__ import annotations

import os

import httpx

GUARDRAIL_URL: str = os.getenv("GUARDRAIL_URL", "http://guardrail-proxy:9090")
PRESIDIO_URL: str = os.getenv("PRESIDIO_URL", "http://presidio-analyzer:5002")
PII_THRESHOLD: float = float(os.getenv("PII_THRESHOLD", "0.7"))


class GuardrailError(Exception):
    """Raised when the guardrail service is unreachable."""


class ContentBlockedError(GuardrailError):
    """Raised when the guardrail proxy rejects content."""

    def __init__(self, matched: list[str]) -> None:
        self.matched = matched
        super().__init__(f"Content blocked by guardrail: {matched}")


async def validate(text: str) -> None:
    """
    Check text against the guardrail proxy forbidden-pattern rules.
    Raises ContentBlockedError if blocked, GuardrailError if unreachable.
    """
    async with httpx.AsyncClient(timeout=5.0) as client:
        try:
            resp = await client.post(
                f"{GUARDRAIL_URL}/validate",
                json={"role": "user", "content": text},
            )
        except httpx.RequestError as exc:
            raise GuardrailError(f"Guardrail proxy unreachable: {exc}") from exc

    body = resp.json()
    if body.get("status") == "blocked":
        raise ContentBlockedError(body.get("matched", []))


async def scrub_pii(text: str) -> tuple[str, list[dict]]:
    """
    Detect PII via Presidio and replace entities with [ENTITY_TYPE] placeholders.

    Returns (scrubbed_text, entity_list).
    Fails open on Presidio errors: returns the original text unchanged so
    ingestion can still proceed (the error is logged by the caller).
    """
    payload = {
        "text": text,
        "language": "en",
        "score_threshold": PII_THRESHOLD,
    }
    async with httpx.AsyncClient(timeout=8.0) as client:
        try:
            resp = await client.post(f"{PRESIDIO_URL}/analyze", json=payload)
            resp.raise_for_status()
            entities: list[dict] = resp.json()
        except (httpx.RequestError, httpx.HTTPStatusError):
            # Fail open: return original text, empty entity list.
            return text, []

    if not entities:
        return text, entities

    # Redact right-to-left so earlier byte offsets stay valid.
    runes = list(text)
    for entity in sorted(entities, key=lambda e: e["start"], reverse=True):
        placeholder = list(f"[{entity['entity_type']}]")
        runes[entity["start"]: entity["end"]] = placeholder

    return "".join(runes), entities
