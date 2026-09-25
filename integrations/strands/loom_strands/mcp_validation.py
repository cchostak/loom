"""Pinned signed contracts and strict schemas; authenticated content stays untrusted."""
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator

from loom_strands.connection import LoomFailure
from loom_strands.contract_key import PUBLIC_KEY

PUBLIC_KEY_PATH = Path('/etc/loom/mcp-public.pem')
TEXT_RESULT = {
    'type': 'object', 'required': ['content'], 'additionalProperties': False,
    'properties': {
        'content': {'type': 'array', 'minItems': 1, 'maxItems': 256, 'items': {
            'type': 'object', 'additionalProperties': False, 'required': ['type', 'text'],
            'properties': {'type': {'const': 'text'}, 'text': {'type': 'string', 'maxLength': 65536}}}},
        'isError': {'type': 'boolean'},
        '_meta': {'type': 'object', 'additionalProperties': False, 'properties': {
            'loom/provenance': {'type': 'object'}}},
    },
}


def contract():
    """Verify the offline publisher's signature before trusting any tool definition."""
    try:
        signed = json.loads(Path(__file__).with_name('tool_contract.json').read_text())
        payload = base64.b64decode(signed['payload'], validate=True)
        signature = base64.b64decode(signed['signature'], validate=True)
        Ed25519PublicKey.from_public_bytes(PUBLIC_KEY).verify(signature, payload)
        result = json.loads(payload)
        if result['version'] != 1:
            raise ValueError('version')
        return {tool['name']: tool for tool in result['tools']}
    except (ValueError, KeyError, InvalidSignature, OSError):
        raise LoomFailure('Tool contract verification failed') from None


def verify_response(response, request_body, session):
    """Authenticate response bytes, freshness and exact request/session binding."""
    try:
        issued = response.headers['x-loom-mcp-issued']
        if abs(time.time() - int(issued)) > 45:
            raise ValueError('stale response')
        key = serialization.load_pem_public_key(PUBLIC_KEY_PATH.read_bytes())
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError('invalid key')
        def digest(b):
            return hashlib.sha256(b).hexdigest()
        message = '\n'.join(('loom-mcp-v1', digest(request_body), digest(response.content),
                            digest(session.encode()), response.headers['x-loom-trace-id'],
                            str(response.status_code), issued)).encode()
        key.verify(base64.b64decode(response.headers['x-loom-mcp-signature'], validate=True), message)
    except (OSError, ValueError, KeyError, InvalidSignature):
        raise LoomFailure('MCP response authentication failed') from None


def validate_request(message, tools):
    """Reject unexpected capabilities and arguments before sending an invocation."""
    if message.get('method') != 'tools/call':
        return
    params = message.get('params', {})
    if set(params) - {'name', 'arguments', '_meta'}:
        raise LoomFailure('MCP argument schema denied')
    name = params.get('name', '').removeprefix('filesystem_')
    if name not in tools:
        raise LoomFailure('Unregistered MCP capability')
    arguments = params.get('arguments', {})
    if not Draft202012Validator(tools[name]['inputSchema']).is_valid(arguments):
        raise LoomFailure('MCP argument schema denied')
    path = arguments['path']
    if len(path) > 4096 or '\\' in path or any(ord(c) < 32 for c in path) or '..' in path.split('/'):
        raise LoomFailure('MCP resource denied')
    if str(PurePosixPath(path)) != path or (path != '/workspace' and not path.startswith('/workspace/')):
        raise LoomFailure('MCP resource denied')


def validate_result(method, result, tools):
    """Return only contract-approved tool definitions and bounded textual results."""
    if method == 'tools/list':
        if set(result) != {'tools'} or not isinstance(result['tools'], list) or len(result['tools']) > len(tools):
            raise LoomFailure('MCP tool discovery schema denied')
        seen = set()
        for tool in result['tools']:
            name = tool.get('name', '').removeprefix('filesystem_')
            if name in seen or name not in tools:
                raise LoomFailure('MCP tool contract denied')
            seen.add(name)
            normalized = dict(tool, name=name)
            if normalized != tools[name]:
                raise LoomFailure('MCP tool contract changed')
    elif method == 'tools/call':
        if not Draft202012Validator(TEXT_RESULT).is_valid(result):
            raise LoomFailure('MCP result schema denied')
        for block in result['content']:
            if any(ord(c) < 32 and c not in '\n\r\t' for c in block['text']):
                raise LoomFailure('MCP result contains control characters')
    return result
