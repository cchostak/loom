# Enterprise lab implementation

Status: implementation in progress. This document is the plan and evidence ledger;
planned controls are not production assurances.

## Architecture and sequence

1. Add a standards-based local issuer using pinned `oidc-provider`, real PKCE login
   and client credentials. Loom validates JWT access tokens against pinned issuer,
   audience, algorithm and JWKS; identity mappings remain server-owned. Publish
   MCP protected-resource metadata. Keep local opaque authentication as the default.
2. Add an isolated enterprise Compose project. Put workloads on internal networks,
   disable external DNS forwarding and make Squid the provider connector's only
   Internet path. Only the connector receives provider credentials. Exact-action
   dispatch authorizations constrain gateway access to that connector.
3. Add durable transactional state for shared admission/operation budgets and
   revocation; evaluate pinned Agentgateway remote rate limiting before selecting
   its integration. Test two instances, crash/restart and storage failure. State
   reservations are conservative; missing usage must not refund admitted work.
4. Add a separate authenticated append-only audit service with hash-chain evidence,
   and transactional approvals with independently authenticated operators. Execute
   only an inert receipt, with reauthorization and one-use consumption in the same
   transaction. An audit administrator/host remains trusted.
5. Add tenant-scoped document retrieval, live source ACL checks and signed lineage
   for derived documents. Recheck ancestor access on every read; signatures never
   upgrade trust or grant permission to export to a model.

## Delivery and checks

Keep the default stack and Strands lab operational. Provide enterprise bootstrap,
start/test/stop commands, generated secrets and pinned build dependencies. Tests
must exercise real issuer tokens, actual Loom model/MCP policy and network paths;
unit tests cover malformed input, race/replay, revocation and transactional state.
Document any unavailable feature or residual boundary explicitly. No external paid
model calls are required for regression evidence.

Local issuer HTTP is restricted to loopback and internal lab networks. This is a
local protocol exercise; remote use requires HTTPS and authenticated service links.
