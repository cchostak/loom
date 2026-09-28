# Loom security threat model

Assessment: 2026-09-28. Scope includes Compose, AgentGateway perimeter trust broker,
ExtAuthz gRPC service, stdio SafeFS MCP, Python ingestion pipeline, swarm simulation, and CI.
This architecture offloads perimeter security, identity verification, rate limiting, and cost
controls to AgentGateway, while retaining deep cryptographic validation in custom ExtAuthz.

## Assets, actors and boundaries

Assets: provider credentials, workspace contents, prompts and responses, raw
Bronze documents, derived context, security policy, identities, budget state,
audit events and CI signing authority. Actors include developers, agents,
external content authors, model providers, MCP implementations, CI contributors,
and operators. Treat models, files, tools and retrieved material as untrusted.

Boundaries:
1. **Perimeter Trust Boundary**: Client/Agent/IDE to AgentGateway. AgentGateway is the
   primary perimeter trust broker. It terminates public and edge ingress, authenticates
   Dex OIDC/JWT bearer tokens, evaluates CEL claim verification rules, applies token bucket
   rate limits, and tracks dollar spend budgets via its native model catalog and SQLite store.
2. **Deep Validation Boundary**: AgentGateway to Control Plane via gRPC ExtAuthz (`:9001`).
   For complex MCP tool calls, AgentGateway delegates request inspection to ExtAuthz, which
   validates the offline signed `tool_contract.json` (Ed25519), validates schemas, blocks
   path traversal escapes, and detects prompt injection markers.
3. **Backend Zero-Trust Boundary**: AgentGateway to Backend Agents and SafeFS MCP Server.
   All backend communication occurs across mutual TLS (mTLS) with short-lived SPIFFE/SPIRE
   workload identities (`spiffe://loom.local/workload/...`).
4. **Guardrail & Content Inspection Boundary**: AgentGateway to Guardrail Proxy (`/validate`).
   Prompts and completions are inspected fail-closed for PII and secrets.
5. **Storage & Workspace Boundary**: SafeFS descriptor-relative `O_NOFOLLOW` access strictly
   constrained to `/workspace`.

Ingress includes HTTP prompts, MCP arguments, files, tool results, retrieval,
configuration, environment and PRs. Egress includes OpenRouter, MCP results,
traces/logs, IDE networking and optional embedding downloads. Reads can export
secrets; writes, shell execution, deployments and external messages are
privileged even when phrased as harmless natural-language requests.

## Controls and Perimeter Defense Architecture

AgentGateway serves as the primary perimeter trust broker:
- **Edge Authentication & Claims**: Native `jwtAuth` validates Dex IdP JWTs against JWKS.
  Common Expression Language (CEL) policies enforce:
  `jwt.claims["iss"] == "https://dex.loom.local" && jwt.sub != ""`
- **Edge Rate Limiting & Cost Ceilings**: Native `localRateLimit` enforces 60 RPM and
  100k tokens/hour. Built-in `apiKey.budgets` and `modelCatalog` enforce dollar caps ($50/day)
  and token ceilings, failing closed before request dispatch.
- **MCP Tool Capability Filtering**: Edge CEL policy filters tool calls (`read_text_file`,
  `list_directory`), blocking unknown capabilities at the gateway.
- **Delegated ExtAuthz Deep Validation**: Complex schema validation, path traversal checks,
  injection marker detection, and Ed25519 signature sealing are executed by the dedicated
  gRPC ExtAuthz service (`control-plane:9001`).
- **Telemetry Ingestion & Attestation**: OTel Collector routes traces to the Normalizer,
  which appends SPIFFE workload identity to spans before storing findings in the compliance queue.

## Abuse cases and invariants

* **Spoofed identity/confused deputy**: AgentGateway validates Dex JWT signatures and CEL
  claims at the edge; inbound identity headers confer no authority and are not forwarded.
  Internal communication is authenticated via SPIFFE SVIDs.
* **Injection/tool misuse**: Untrusted content cannot grant tool capability. Edge CEL policies
  allow only contract-approved tools. ExtAuthz performs deep schema checks and rejects
  prompt injection markers.
* **Traversal/races**: Workspace reads use an OS-rooted file API (`O_NOFOLLOW`) at execution
  time; ExtAuthz blocks paths outside `/workspace`, `..` sequences, and backslashes before dispatch.
* **Exfiltration**: Secret/PII detectors reject rather than claiming to transform
  bytes which are still forwarded. Detector failure rejects. No raw bodies,
  headers, errors or arguments in security events.
* **Resource exhaustion**: AgentGateway natively enforces request rate limits (60 RPM)
  and dollar budgets ($50/day block) at the perimeter. Clients cannot reset budgets by
  inventing session headers.
* **Laundering**: Data provenance retains untrusted classification on transformation;
  no production delegation grant exists in this increment.
* **Fail open**: Unavailable/malformed policy, auth or guardrail responses deny.
  Audit write failure prevents dispatch. Trace loss is not authorization loss.
* **Supply chain**: Immutable action pins, enforced vulnerability thresholds,
  image scans and build metadata; no runtime dependency acquisition for MCP.

## Residual compromise scenarios

Host/root or a compromised IDE can read its mounted workspace and use its own
network/credentials outside Loom. Gateway compromise can use its provider key
and bypass the application boundary from inside its network. Local audit storage
can be changed by the host. Regex/Presidio are fallible detectors, not proof of
confidentiality. A malicious file can carry instructions even when reads are
properly scoped. Review docs/security-roadmap.md before production deployment.

## Threat Composer model artifacts

A formal threat model was generated using the Threat Modeling MCP Server across 9 lifecycle phases (including Phase 7.5 code validation against active code):
- **Threat Composer JSON**: [threat-model-composer.tc.json](.threatmodel/threat-model-composer.tc.json)
- **Detailed Threat Model Report**: [threat-model-composer.md](.threatmodel/threat-model-composer.md)

