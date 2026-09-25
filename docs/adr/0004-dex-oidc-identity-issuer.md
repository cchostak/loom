# ADR 0004 — Dex as the Stage 1 OIDC Identity Issuer

Date: 2026-09-25  
Status: **Accepted**

---

## Context

The [security roadmap](../security-roadmap.md) identifies Stage 1 (Identity) as
the next required increment before a shared production deployment. The
requirement is:

> *Lightweight standards-based issuer; evaluate Dex against the required
> access-token and MCP flows. Adapt Loom's existing `Authenticator`; explicit
> issuer-to-principal/workload/tenant/scope mapping.*

Loom's current authentication is a local opaque bearer token stored in a flat
JSON file (`credentials.json`). This is deliberately lightweight for local
use, but the roadmap explicitly requires an OIDC issuer for any shared
deployment.

The question considered in this ADR is which OIDC issuer to adopt: a
purpose-built alternative (Kanidm, Keycloak, Authentik) versus a thin
federation relay (Dex), versus building a minimal custom issuer.

---

## Decision

Use **Dex v2.43.x** (`ghcr.io/dex-idp/dex`) as the local OIDC issuer for
Stage 1.

---

## Rationale

### Why not a heavier IdP (Kanidm, Keycloak, Authentik)?

Loom's principals are **service identities** — IDE process, pipeline agent,
Strands agents — not human users with email accounts. These systems solve
account management, self-service password reset, LDAP/RADIUS integration, and
MFA enrollment. Loom does not need any of that at Stage 1.

| Concern | Heavier IdP | Dex |
|---|---|---|
| Account management UI | Full | None (not needed) |
| Human-flow features | Yes | Delegated to connector |
| Compose weight | High (own DB, TLS, admin bootstrap) | Low (single binary) |
| Operational complexity | High | Low |
| `client_credentials` grant | Supported | Supported |
| `at+jwt` (RFC 9068) | Varies | Yes via OAuth2 access tokens |
| PKCE enforcement | Varies | Configurable |

### Why not build a minimal custom issuer?

The `security.OIDC` authenticator in `docker/security/oidc.go` already
implements the consumer side (discovery, JWKS, RS256 `at+jwt` validation,
binding to `IdentityContext`). Building an issuer would duplicate the signing
and key-management work that Dex already provides correctly, with test coverage
and a known security track record.

### Why Dex fits

- **Thin by design** — Dex is an OIDC relay, not a full IdP. In Stage 1 we
  use static client credentials (no connector). In production it would relay to
  GitHub, SAML, or LDAP without changing the Loom consumer side.
- **`client_credentials` flow** — service accounts authenticate with a client
  secret; no browser redirect or PKCE needed for daemon workloads.
- **PKCE enforcement** — enforced on authorization-code flows via
  `responseTypes: [code]` in the Dex config.
- **Key rotation** — Dex rotates signing keys automatically; `oidc.go` fetches
  JWKS on every request (no stale-key cache).
- **Pinned image** — `Dockerfile.dex` pins the full SHA-256 digest.
- **Already tested** — the `TestOIDCAccessTokens` suite covers all critical
  token validation paths against a real JWKS test server; Dex just needs to
  produce a conformant token.

---

## Consequences

### Positive

- Local `make up` remains unchanged (Dex is an opt-in overlay with
  `make dex-up`).
- `enterprise/configure.go` gains an identity-only mode: Dex provides auth,
  local audit and budgets are preserved. No remote state service is required
  for Stage 1.
- The `LOOM_ENTERPRISE_CONFIG` env var activates the OIDC path automatically
  when the Compose overlay is used; removing the overlay reverts to opaque
  tokens with no code change.
- Dex can later relay to GitHub, LDAP, or SAML by adding a connector to
  `config/dex.yaml` without touching the Loom consumer code.

### Negative / Risks

- **`client_credentials` subject** — Dex uses `client_id` as the token
  `sub` in client-credentials flow. The OIDC binding in `configure.go` maps
  `(subject == client_id, client_id == client_id)` to identity. This is a
  single-field match; a multi-field identity claim would require a Dex connector
  or token enrichment plugin.
- **No revocation at Stage 1** — Dex does not support RFC 7009 token
  revocation out of the box. Token lifetime is capped at 10 minutes in `dex.yaml`
  and the OIDC authenticator enforces a 10-minute maximum. Revocation remains a
  follow-on item (roadmap P1: durable quotas/revocation).
- **Static secrets in dex.yaml** — `config/dex.yaml` is rewritten by
  `bootstrap_dex.py` to include client secrets. The file must not be committed
  after initialization. The bootstrap script idempotency check and `.gitignore`
  entries prevent accidental commit; a production deployment would use a
  secrets manager.

---

## Alternatives considered

| Alternative | Reason rejected |
|---|---|
| Kanidm | Full IdP with account management UI, LDAP server, group engine. Solves a different problem. |
| Keycloak | Heavy Java runtime; significant Compose overhead for a local lab. |
| Custom minimal issuer | Duplicates key management Dex already provides correctly. |
| Continue with opaque tokens | Does not satisfy the roadmap P0 OAuth/OIDC requirement. |

---

## Implementation summary

| File | Change |
|---|---|
| `docker/Dockerfile.dex` | Pinned Dex image, `nobody` user, `/config/dex.yaml` entrypoint |
| `config/dex.yaml` | Skeleton; `bootstrap_dex.py` writes `staticClients` block |
| `docker-compose.dex.yml` | Compose overlay; adds `dex` service and `identity-net` |
| `scripts/bootstrap_dex.py` | Generates per-workload client secrets and `config/oidc.json` |
| `docker/enterprise/configure.go` | Identity-only mode when remote service fields are empty |
| `docker/enterprise/configure_dex_test.go` | Tests for identity-only mode and metadata endpoint |
| `Makefile` | `dex-init`, `dex-up`, `dex-down`, `dex-token`, `dex-clean` targets |

---

## Acceptance criteria (from roadmap Stage 1)

- [ ] Real login with authorization code and PKCE (human flow, future)
- [x] `client_credentials` token issuance for service accounts
- [x] Resource-specific access tokens (audience = `https://loom.local/api`)
- [x] Reject ID tokens (typ check: `at+jwt` required in `oidc.go`)
- [x] Reject wrong issuer / audience / expired / forged tokens (covered by `TestOIDCAccessTokens`)
- [x] Test signing-key rotation (covered by `TestOIDCAccessTokens` `key rotation` case)
- [x] Issuer outage denies (covered by `TestOIDCAccessTokens` `issuer outage` case)
- [ ] Scope escalation in token claims is blocked by binding (tested, `scope escalation` case passes through binding intersection only)
