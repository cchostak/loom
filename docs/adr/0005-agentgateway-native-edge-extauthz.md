# ADR 0005 — AgentGateway Native Edge Policy Offload and gRPC ExtAuthz Architecture

Date: 2026-09-28  
Status: **Accepted**

---

## Context

Loom's initial security perimeter relied on custom in-process Go middleware components (`docker/security/budget.go`, `docker/security/circuit.go`, `docker/enterprise/ratelimit.go`, `docker/security/oidc.go`, and `docker/security/auth.go`) to perform edge authentication, rate limiting, and token/dollar budget tracking. While functional, maintaining custom middleware for generic edge concerns introduced architectural bloat, operational overhead, and redundant parsing logic ahead of the gateway.

AgentGateway provides native, production-grade edge security primitives including:
1. Native JWT authentication and Common Expression Language (CEL) claim verification rules (`jwtAuth`, `authorization`).
2. Built-in rate limiting and token bucket enforcement (`localRateLimit`).
3. Native dollar and token budget tracking backed by an embedded database (`apiKey.budgets`).
4. Built-in model catalog pricing rates (`modelCatalog`).
5. Native Model Context Protocol (MCP) tool allowlisting via CEL (`mcpAuthorization`).
6. Delegation of deep payload authorization via gRPC External Authorization (`extAuthz`).

We sought to lean out Loom's custom codebase by offloading perimeter identity verification, rate limiting, and cost controls to AgentGateway's native capabilities, while strictly retaining custom Go code for deep cryptographic validation (the ExtAuthz pattern) and compliance telemetry normalization.

---

## Decision

1. **Deprecate Custom Edge Middleware**:
   Delete redundant Go implementations:
   - `docker/security/budget.go` (in-memory budget controller)
   - `docker/security/circuit.go` (in-memory circuit breaker)
   - `docker/enterprise/ratelimit.go` (Envoy external rate limit service adapter)
   - `docker/security/oidc.go` (custom Dex OIDC validator)
   - `docker/security/auth.go` (custom local credential registry)

2. **Configure Native AgentGateway Edge Policies (`config/agentgateway-config.yaml` & `config/policy.json`)**:
   - **Dex OIDC / JWT Authentication**: AgentGateway validates incoming JWT bearer tokens against Dex IdP using `jwtAuth` and enforces claim validity via CEL:
     `jwt.claims["iss"] == "https://dex.loom.local" && jwt.sub != ""`
   - **Edge Rate Limiting**: AgentGateway applies native local rate limiting (60 RPM) and token bucket limits (100k tokens/hour).
   - **Cost Controls & Dollar Budgets**: AgentGateway tracks input/output token rates via `modelCatalog` and enforces virtual key limits:
     - Daily dollar budget ($50.00 / day, block on breach)
     - Hourly token budget (100,000 tokens / hour, block on breach)
   - **Tool Capability Allowlist**: AgentGateway enforces MCP tool permissions via CEL:
     `mcp.tool.name in ["read_text_file", "list_directory"]`

3. **Establish Dedicated gRPC ExtAuthz Service (`docker/security/mcp_signature.go`)**:
   - AgentGateway delegates deep payload checks to `control-plane:9001` via `envoy.service.auth.v3.Authorization`.
   - The ExtAuthz service verifies `tool_contract.json` against the publisher's Ed25519 public key.
   - For `tools/call`, ExtAuthz performs deep JSON schema inspection, path traversal prevention (blocking `..`, backslashes, unnormalized paths, and paths outside `/workspace`), prompt injection marker detection, and seals validated requests with `X-Loom-MCP-Validated` and Ed25519 signature headers.

4. **Zero-Trust Backend Communication**:
   - Validated requests from AgentGateway to backend agents and MCP servers use SPIFFE/SPIRE mTLS SVIDs (`spiffe://loom.local/workload/...`).

5. **Telemetry Normalization Pipeline (`normalizer.go`)**:
   - OpenTelemetry Collector routes AgentGateway trace, metric, and cost outputs to `http://normalizer:8080/v1/traces`.
   - `normalizer.go` ingests standard OTel spans, extracts GenAI cost and token metrics, appends SPIFFE workload identity, and transforms records into the `UnifiedFinding` governance schema.

---

## Operational Flow

```text
Client / Agent / IDE
        │
        ▼ (HTTPS / JWT Bearer)
AgentGateway (Edge Perimeter)
  ├── 1. Dex OIDC JWT Validation (CEL Claims)
  ├── 2. Native Rate Limiting (60 RPM, 100k tokens/hr)
  ├── 3. Dollar & Token Budget Tracking (Native Catalog & DB)
  └── 4. Tool Name Allowlist (CEL)
        │
        ▼ (gRPC ExtAuthz: envoy.service.auth.v3)
Control Plane ExtAuthz Service (:9001)
  ├── 5. Cryptographic Contract Verification (Ed25519)
  ├── 6. Deep JSON Schema Validation (tool_contract.json)
  ├── 7. Path Traversal & Injection Marker Inspection
  └── 8. Cryptographic Sealing (X-Loom-MCP-Signature)
        │
        ▼ (SPIFFE/SPIRE mTLS)
Backend Agent / MCP SafeFS Server
        │
        ▼ (OTel Traces & Spans)
OTel Collector Contrib
        │
        ▼ (HTTP /v1/traces)
Normalizer Service (Appends SPIFFE Workload Context)
        │
        ▼ (SQLite Queue)
Unified Finding Governance Schema
```

---

## Consequences

### Positive
- **Reduced Attack Surface**: Custom edge authentication, parsing, and budget tracking code is eliminated in favor of hardened AgentGateway native code.
- **Improved Performance**: Token bucket rate limits, dollar budget enforcement, and claim validation occur at the edge without reaching backend Go services.
- **Fail-Closed Deep Security**: High-assurance checks (Ed25519 publisher signature, path traversal, injection detection) remain isolated in a dedicated gRPC ExtAuthz service.
- **Zero Regression in Zero-Trust Posture**: All backend service interactions require SPIFFE/SPIRE mTLS; telemetry is enriched with immutable SPIFFE workload identities.

### Negative
- **AgentGateway Dependency**: AgentGateway v1.5.0+ is required as the primary edge entry point.
- **ExtAuthz Hop**: Delegated deep schema inspection introduces a low-latency gRPC round-trip between AgentGateway and the control-plane container for tool calls.
