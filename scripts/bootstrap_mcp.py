"""Provision a local response-signing key without publishing its private bytes."""
from pathlib import Path
import subprocess
import secrets


def provision(identity: Path):
    """Keep a consistent key pair; never silently replace an existing key."""
    for name in ("normalizer-ingest", "normalizer-read", "normalizer-key", "otel-control-token"):
        path = identity / name
        if not path.exists():
            path.write_text(secrets.token_urlsafe(48))
            path.chmod(0o444)
    private, public = identity / 'mcp-key.pem', identity / 'mcp-public.pem'
    if private.exists() != public.exists():
        raise RuntimeError('Partial MCP signing key setup')
    if not private.exists():
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'ED25519', '-out', str(private)], check=True, capture_output=True)
        subprocess.run(['openssl', 'pkey', '-in', str(private), '-pubout', '-out', str(public)], check=True, capture_output=True)
        private.chmod(0o444)
        public.chmod(0o444)
    derived = subprocess.run(['openssl', 'pkey', '-in', str(private), '-pubout'], check=True, capture_output=True).stdout
    if derived != public.read_bytes():
        raise RuntimeError('MCP signing key mismatch')
