# Security implementation roadmap

This plan prioritizes mandatory mediation over prompt-string additions. The
first-increment table below is implemented; limitations and tested scope are in
[security-implementation.md](security-implementation.md). Follow-on entries
remain open and block a shared production deployment where marked P0/P1.

| Priority | Work | Acceptance criteria |
| --- | --- | --- |
| P0 | Authenticated HTTP boundary before Agentgateway | Unknown/expired credential denies; identity headers cannot grant authority; direct gateway not published or reachable from IDE network |
| P0 | Scoped MCP execution | Only strict read/list arguments; unknown methods deny; OS-rooted open resists symlink races; workspace mount read-only; no npm/runtime downloads |
| P0 | Guardrail and ingestion failure semantics | Bad schema, analyzer failure and sensitive data reject; no raw body in errors; unsafe input never dispatched |
| P0 | Exposure and privilege | Published ports loopback only; no host OTLP/guardrail; cap drop, non-root and limits on core services |
| P1 | Security context and policy | Versioned default-deny policy; actor/workload/session/resource/destination decisions with IDs; taint representation |
| P1 | Audit and budgets | Pre-dispatch audit plus result correlation; no raw arguments; rate/concurrency/call/input/output/time limits enforced |
| P1 | Action-bound approval contract | Exact canonical action + actor + policy + expiry bound; tamper/replay/expiry tests; no write executor until operator authentication exists |
| P1 | Real gateway regression suite | Authenticate, initialize MCP, discover/call allowed read and reject unknown/write/traversal through Compose; dependency failures tested separately |
| P2 | Supply chain and telemetry | SHA actions, blocking scans, image SBOM/provenance; allowlisted exported span fields; configuration regression tests |

## Next lab increments

These controls can be built and exercised locally. A shared production deployment
adds operational requirements, but is not a prerequisite for implementing the
security protocols. The stages below are planned, not implemented. Keep each
stage keyless in CI and run it through the actual Loom/Agentgateway boundary.
Use an optional enterprise lab Compose overlay with isolated state and generated
credentials, retaining the lightweight default quickstart.

| Stage | Local implementation | Evidence required before closing the gap |
| --- | --- | --- |
| 1. Identity | Lightweight standards-based issuer; evaluate Dex against the required access-token and MCP flows. Adapt Loom's existing `Authenticator`; explicit issuer-to-principal/workload/tenant/scope mapping. | Real login with authorization code and PKCE; resource-specific access tokens; reject ID tokens, wrong issuer/audience, expired/forged tokens and forged identity headers; test signing-key rotation and issuer outage. |
| 2. Egress | Squid destination allowlist; internal-only workload networks; dedicated provider connector holding the provider credential. | Compromised IDE, agent and gateway cannot reach arbitrary Internet, metadata or management endpoints, even after removing proxy settings. Test direct IP, IPv6, DNS, CONNECT, redirects and proxy outage; allowed provider traffic still succeeds. |
| 3. Shared quotas | Prefer Agentgateway's remote rate-limit integration with a persistent shared store; evaluate its database-backed LLM budgets separately. | Two gateway instances share the same authenticated quota; restart/crash cannot restore admitted capacity beyond an explicitly documented bound; store outage denies; different tenants remain isolated. Test missing provider usage and concurrent requests at the limit. |
| 4. Durable audit and approval | Separate authenticated audit service and storage; small approval service with separate operator identity and transactional one-use records. | Workload cannot alter accepted audit records; audit outage prevents protected dispatch; replayed, mutated, expired or revoked approvals cannot execute. Use an inert test executor before granting real writes. |
| 5. Retrieval and delegation | Persist source IDs, ACLs and lineage with stored and derived data; sign or attest lineage at trusted services. | A poisoned document stays untrusted through retrieval, summary and handoff; revoked source access propagates; another tenant cannot retrieve it; valid signatures do not grant export permission. |

Identity needs separate human and workload flows. An OIDC ID token proves login
to its client; it is not automatically an access token for Loom's API. Select a
pinned issuer release only after testing its audience/resource semantics, token
validation or introspection, and MCP protected-resource discovery. Validate nonce
in the OIDC login flow and state/PKCE in the authorization-code flow. Workload
credentials must not silently inherit a human's full permissions.

Squid is an enforcement point only when workloads have no alternate route.
An `HTTPS_PROXY` environment variable alone is not containment. Keep arbitrary
CONNECT tunnels unavailable to agents and the IDE; allow provider access only
from the dedicated connector. Restrict destination names, ports and resolved
addresses, disable proxy caching and sensitive request logging, and preserve TLS
verification. A destination allowlist still does not authorize which data may be
sent to an allowed provider. Package/extension acquisition should use a separate
reviewed bootstrap path, not broad runtime egress exceptions.

Agentgateway is the preferred enforcement location for model consumption limits.
Its documented database-backed budgets charge after a response and flush in-memory
counts every five seconds; they are not a strict pre-dispatch spend reservation.
Remote rate limits support shared counters through an external service. Verify
both features against the repo's pinned v1.5.0 binary and existing configuration
before adopting them. Derive quota descriptors from authenticated identity, never
client-supplied headers or arbitrary workflow IDs. Track request rate, lifetime
operations, concurrency, model spend and in-flight revocation as separate controls;
one counter does not satisfy every requirement. Persistence settings and atomic
updates must be tested under crashes, not inferred from adding a database volume.

The same approach applies to the remaining roadmap: reuse small established
components, then test the boundary and its failure behavior. A signature cannot
prove a source is truthful; an approval row needs atomic consumption; a remote
log service is not immutable against its own administrator. State exactly which
actor each local implementation constrains.

Implementation references checked 25 September 2026:
[Dex OAuth configuration](https://dexidp.io/docs/configuration/oauth2/),
[Squid access controls](https://www.squid-cache.org/Doc/config/http_access/),
[Agentgateway budgets](https://agentgateway.dev/docs/standalone/latest/documentation/llm/cost-controls/budget-limits/),
and [Agentgateway remote rate limits](https://agentgateway.dev/docs/standalone/latest/documentation/configuration/resiliency/rate-limits/).

## Required follow-on work before shared production deployment

* **P0: OAuth/OIDC deployment** — implement `Authenticator` using issuer-pinned
  discovery/JWKS, algorithm allowlist, audience/expiry/nonce validation and key
  rotation. HTTP MCP must implement the current protected-resource metadata and
  OAuth flow. Acceptance: wrong issuer/audience, expired and forged tokens deny;
  no token passthrough. Local opaque credentials are explicitly not OAuth.
* **P0: Container compromise egress** — move model credentials into a dedicated
  provider connector and enforce destination allowlists at a firewall/proxy.
  Acceptance: compromised gateway/IDE/MCP cannot connect to arbitrary Internet
  destinations or reach another control service's management plane.
* **P1: Durable quotas/revocation** — replace process-local budget state with an
  atomic store keyed by authenticated tenant/workload/session. Acceptance:
  restarts and multiple replicas cannot reset calls/spend; revocation cancels
  in-flight operations; reconcile actual provider usage against reservations.
* **P1: Provenance through retrieval** — persist signed source lineage through
  Bronze/Silver/Gold, summaries and inter-agent handoffs. No detector result may
  upgrade trust. Acceptance: poisoned memory remains tainted after each transform;
  tenant isolation and ingestion/auth quotas tested end to end.
* **P1: Remote audit sink** — append-only authenticated collector with retention,
  integrity checkpoints and independent access control. Acceptance: host/container
  cannot rewrite accepted events; outage follows explicit dispatch policy.
* **P1: Operator approvals** — separate operator identity/step-up authentication,
  durable one-time consumption and executor reauthorization. Acceptance: mutated,
  expired, replayed or revoked approval cannot execute. Never expose signing keys
  to requesting agents. This increment must not enable privileged writes.
* **P2: Shadow policy rollout** — evaluate a candidate policy alongside the live
  policy and record decision differences without granting candidate authority.
  Acceptance: shadow allows never override live denies; versioned rollback is
  tested before activation.
* **P2: Broader MCP tools** — one schema/resource adapter per tool, isolated server
  identities and pinned metadata. Acceptance: metadata cannot introduce new grants;
  attacker-controlled paths/URLs/arguments never expand capability.
* **P2: Release verification** — verify signed provenance subject digest and trusted
  builder/ref before deployment; record exceptions with owner/rationale/expiry.
  Build metadata alone is not a SLSA certification or deployment admission gate.
* **P3: Strong classifiers and evaluation** — implement detector adapters, corpus
  fuzzing and independent model evaluation. Measure false positives and negatives;
  never treat a demonstration's attack-block percentage as production assurance.

## Reference models (checked 2026-09-23)

* [OWASP Agentic Top 10](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/)
* [OWASP Agent Control Standard and LLM 2026 announcement](https://genai.owasp.org/2026/09/01/owasp-genai-security-project-unveils-2026-top-10-for-llm-applications-new-agent-control-standard-and-sponsors-as-community-tops-30000-members/)
* [MCP authorization 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
* [NIST AI 600-1](https://doi.org/10.6028/NIST.AI.600-1)
* [SLSA 1.2](https://slsa.dev/spec/v1.2/)
* [GitHub secure use](https://docs.github.com/en/actions/reference/security/secure-use)

These guide threat coverage; no compliance certification is claimed.
