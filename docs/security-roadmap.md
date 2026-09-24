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
