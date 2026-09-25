#!/usr/bin/env python3
"""Provision Dex static client credentials and write OIDC binding for Loom.

Run via 'make dex-init'. Idempotent: skips if both config/dex.yaml clients
block and .loom/dex/ already exist. Re-run is safe only after 'make dex-clean'.

Outputs:
  config/dex.yaml         — Dex static config with generated client secrets
  config/oidc.json        — enterprise OIDC binding for the control plane
  .loom/dex/              — per-workload client secret files (chmod 600)

Security notes:
  - Secrets are never printed to stdout or logged.
  - Client secrets are 48-byte URL-safe random tokens (288 bits of entropy).
  - config/oidc.json references secret file paths; secrets are not inlined.
  - .loom/dex/ is owned by the operator; keep it outside version control.
"""
import json
import os
import secrets
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Workloads that receive a dedicated Dex client.
# Each entry: (client_id, principal, workload, tenant, scopes)
# ---------------------------------------------------------------------------
WORKLOADS = [
    ("loom-ide",      "local-developer", "local-agent",  "local", ["workspace:read", "model:invoke"]),
    ("loom-pipeline", "pipeline-svc",    "pipeline",     "local", ["model:invoke"]),
    ("loom-agent",    "agent-svc",       "agent",        "local", ["model:invoke", "mcp:connect"]),
]

# Dex is reachable from the host for token introspection during bootstrap;
# internal container-to-container URL is used by the control plane.
DEX_ISSUER_INTERNAL = "http://dex:5556/dex"
DEX_ISSUER_HOST     = "http://127.0.0.1:5556/dex"
LOOM_AUDIENCE       = "https://loom.local/api"
LOOM_RESOURCE_URL   = "http://control-plane:8080"


def _read_yaml_header(path: Path) -> str:
    """Return lines up to (not including) the staticClients marker."""
    lines, in_block = [], False
    for line in path.read_text().splitlines(keepends=True):
        if line.startswith("staticClients:"):
            in_block = True
            break
        lines.append(line)
    return "".join(lines)


def bootstrap(root: Path) -> None:
    config_dir = root / "config"
    dex_yaml   = config_dir / "dex.yaml"
    oidc_json  = config_dir / "oidc.json"
    loom_dir   = root / ".loom" / "dex"

    if loom_dir.exists() and oidc_json.exists():
        print("Dex credentials already exist. Run 'make dex-clean' first to re-generate.")
        return

    loom_dir.mkdir(parents=True, exist_ok=True)
    loom_dir.chmod(0o700)

    client_secrets: dict[str, str] = {}
    for client_id, *_ in WORKLOADS:
        client_secrets[client_id] = secrets.token_urlsafe(48)
        secret_path = loom_dir / f"{client_id}.secret"
        with os.fdopen(
            os.open(secret_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w"
        ) as f:
            f.write(client_secrets[client_id])

    # Build Dex staticClients YAML block.
    clients_yaml_lines = ["staticClients:\n"]
    for client_id, principal, workload, tenant, scopes in WORKLOADS:
        secret = client_secrets[client_id]
        # Dex needs the redirect_uri; we use the internal control-plane token endpoint.
        clients_yaml_lines += [
            f"  - id: {client_id}\n",
            f"    secret: {secret}\n",
            f"    name: \"Loom {workload}\"\n",
             "    redirectURIs:\n",
            f"      - {LOOM_RESOURCE_URL}/callback\n",
        ]

    static_passwords_block = "staticPasswords: []\n"

    header = _read_yaml_header(dex_yaml)
    new_yaml = header + "".join(clients_yaml_lines) + "\n" + static_passwords_block
    dex_yaml.write_text(new_yaml)

    # Build OIDC bindings for Loom's enterprise/configure.go.
    # Each binding maps (subject, client_id) → IdentityContext.
    # Subject matches the client_id in client_credentials flow.
    bindings = []
    for client_id, principal, workload, tenant, scopes in WORKLOADS:
        bindings.append({
            "subject":   client_id,
            "client_id": client_id,
            "identity": {
                "principal":      principal,
                "workload":       workload,
                "tenant":         tenant,
                "session":        secrets.token_hex(16),
                "authentication": "oauth-access-token",
                "scopes":         scopes,
            },
        })

    oidc_config = {
        "oidc": {
            "issuer":          DEX_ISSUER_INTERNAL,
            "audience":        LOOM_AUDIENCE,
            "discovery_url":   DEX_ISSUER_INTERNAL + "/.well-known/openid-configuration",
            "jwks_url":        DEX_ISSUER_INTERNAL + "/keys",
            "public_jwks_url": DEX_ISSUER_INTERNAL + "/keys",
            "bindings":        bindings,
        },
        "resource": LOOM_RESOURCE_URL,
        # state_url, audit_url, state_token_file, audit_token_file, dispatch_key_file
        # are populated by the operator when enabling durable enterprise controls.
        # Leave empty to use the local fallback for the identity-only stage.
        "state_url":         "",
        "audit_url":         "",
        "state_token_file":  "",
        "audit_token_file":  "",
        "dispatch_key_file": "",
    }
    oidc_json.write_text(json.dumps(oidc_config, indent=2) + "\n")
    oidc_json.chmod(0o644)

    print(
        f"Dex client secrets written to .loom/dex/ ({len(WORKLOADS)} workloads).\n"
        f"config/dex.yaml updated with staticClients.\n"
        f"config/oidc.json written.\n"
        f"Start Dex with: make dex-up"
    )


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[1]
    try:
        bootstrap(root)
    except FileExistsError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
