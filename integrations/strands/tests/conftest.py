"""Test-only response signer; private key never enters the reference runtime."""
import base64
import hashlib
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from loom_strands import mcp_validation


@pytest.fixture
def mcp_signer(tmp_path, monkeypatch):
    key = Ed25519PrivateKey.generate()
    public = tmp_path / 'mcp-public.pem'
    public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                   serialization.PublicFormat.SubjectPublicKeyInfo))
    monkeypatch.setattr(mcp_validation, 'PUBLIC_KEY_PATH', public)

    def sign(response, request):
        issued = str(int(time.time()))
        trace = 'a' * 32
        session = response.headers.get('mcp-session-id', request.headers.get('mcp-session-id', ''))
        def digest(b):
            return hashlib.sha256(b).hexdigest()
        message = '\n'.join(('loom-mcp-v1', digest(request.content), digest(response.content),
                            digest(session.encode()), trace, str(response.status_code), issued))
        response.headers.update({'x-loom-mcp-issued': issued, 'x-loom-trace-id': trace,
            'x-loom-mcp-signature': base64.b64encode(key.sign(message.encode())).decode()})
        return response
    return sign
