"""Dependency failures must not be mistaken for clean ingestion results."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import AsyncMock, patch

import httpx

spec = importlib.util.spec_from_file_location("guardrail", Path(__file__).resolve().parents[1] / "pipeline/app/guardrail.py")
guardrail = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guardrail)


class PipelineSecurityTests(unittest.IsolatedAsyncioTestCase):
    async def test_validation_requires_explicit_allow(self):
        for status, body in [(500, {}), (200, {}), (200, []), (200, None), (200, {"status": "error"}), (403, {"status": "blocked"})]:
            with self.subTest(status=status, body=body):
                response = httpx.Response(status, json=body, request=httpx.Request("POST", "http://test"))
                client = AsyncMock()
                client.__aenter__.return_value = client
                client.post.return_value = response
                with patch.object(guardrail.httpx, "AsyncClient", return_value=client):
                    with self.assertRaises(guardrail.GuardrailError):
                        await guardrail.validate("inert fixture")

    async def test_pii_failures_deny(self):
        for status, body in [(503, []), (200, None), (200, {}), (200, [{"start": -1, "end": 1, "entity_type": "X"}]), (200, [{"start": 0, "end": 999, "entity_type": "X"}]), (200, [{"start": "0", "end": 1}])]:
            with self.subTest(status=status, body=body):
                client = AsyncMock()
                client.__aenter__.return_value = client
                client.post.return_value = httpx.Response(status, json=body, request=httpx.Request("POST", "http://test"))
                with patch.object(guardrail.httpx, "AsyncClient", return_value=client):
                    with self.assertRaises(guardrail.GuardrailError):
                        await guardrail.scrub_pii("inert fixture")

    async def test_clean_input_and_redaction(self):
        for function, body in [(guardrail.validate, {"status": "allowed"}), (guardrail.scrub_pii, []), (guardrail.scrub_pii, [{"start": 0, "end": 5, "entity_type": "PERSON"}])]:
            client = AsyncMock()
            client.__aenter__.return_value = client
            client.post.return_value = httpx.Response(200, json=body, request=httpx.Request("POST", "http://test"))
            with patch.object(guardrail.httpx, "AsyncClient", return_value=client):
                result = await function("inert fixture")
                if body and isinstance(body, list):
                    self.assertEqual(result[0], "[PERSON] fixture")

    async def test_outage_denies(self):
        for function in (guardrail.validate, guardrail.scrub_pii):
            client = AsyncMock()
            client.__aenter__.return_value = client
            client.post.side_effect = httpx.ConnectError("offline")
            with patch.object(guardrail.httpx, "AsyncClient", return_value=client):
                with self.assertRaises(guardrail.GuardrailError):
                    await function("inert fixture")
