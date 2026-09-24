You are the principal security architect and senior implementation engineer responsible for elevating this repository:

Your task is to turn Loom from a promising AI gateway/security prototype into a production-oriented, defense-in-depth AI and agent security control plane.

Do not treat this as a documentation exercise and do not solve it by adding more forbidden prompt strings.

Inspect the entire repository first. Understand the actual runtime paths, tests, Docker topology, Agentgateway configuration, MCP authorization, guardrail service, telemetry, CI/CD, adversarial swarm lab, secrets handling, container permissions, and documentation before making changes.

Preserve the useful architecture already present:

* Agentgateway as the mediation point for LLM and MCP traffic.
* Request and response guardrail hooks.
* Default-deny MCP authorization.
* OpenTelemetry-based observability.
* Deterministic adversarial security testing.
* Simple local Docker Compose developer experience.

The goal is to make security decisions based on:

principal + agent/workload + action + resource + arguments + data provenance + trust level + destination + session context + policy

rather than primarily:

content string + tool name

## Security objective

Every meaningful AI interaction should make it possible to answer:

1. Who is acting?
2. Which agent/workload is acting on whose behalf?
3. What exact action is being attempted?
4. Against which resource?
5. With what arguments?
6. What data is being consumed?
7. Where did that data come from?
8. What is its trust and sensitivity classification?
9. Where could the result or data leave the system?
10. Which policy permitted, denied, transformed, or escalated the action?
11. Can the action be stopped before side effects occur?
12. Can an operator reconstruct what happened afterward?

Design and implement toward those invariants.

## Threat model

Assume all of the following are realistic:

* Direct prompt injection.
* Indirect prompt injection from repositories, webpages, files, documents, tool results, MCP resources, retrieved context, and inter-agent messages.
* Agent goal hijacking.
* Legitimate-tool misuse.
* Tool argument manipulation.
* Identity and privilege abuse.
* Confused-deputy attacks.
* Delegation laundering between agents.
* Credential leakage.
* Secret and PII exfiltration.
* Cross-agent exfiltration.
* Malicious or compromised MCP servers.
* Malicious MCP tool metadata or responses.
* Supply-chain compromise.
* Dependency/package compromise.
* Memory/context poisoning.
* Persistent untrusted instructions.
* Unexpected code execution.
* Excessive agency.
* Runaway recursive agent/tool loops.
* Denial-of-wallet/token exhaustion.
* Excessive tool invocation.
* Cascading failures.
* Compromised telemetry.
* Human approval manipulation.
* Fail-open behavior.
* Compromise of one Loom container.
* Compromise of the developer workspace.

Use current OWASP Agent Control Standard guidance, OWASP Top 10 for Agentic Applications, OWASP LLM guidance, NIST AI RMF Generative AI Profile, current MCP security/authorization guidance, conventional zero-trust principles, least privilege, SLSA 1.2 supply-chain practices, and current GitHub Actions security guidance as reference models.

Verify current versions when internet access is available. Do not blindly implement a checklist merely to claim compliance.

## Architectural requirement: introduce first-class security context

Create clean internal types/interfaces equivalent to the following concepts. Adapt names to the language and architecture where appropriate.

### IdentityContext

Must be able to represent at minimum:

* principal/user ID
* agent/workload ID
* tenant/project/workspace ID
* session ID
* authentication method/strength
* delegated-from identity if applicable
* roles/scopes/capabilities

Do not trust caller-supplied identity headers unless they originate from an authenticated trusted boundary.

### ActionRequest

Represent:

* action category
* model or tool
* tool method
* structured arguments
* target resource
* destination
* expected side-effect class
* operation risk class
* requesting IdentityContext

Do not reduce authorization to tool-name matching.

### DataContext

Represent:

* source/provenance
* producer
* trust level
* sensitivity/classification
* whether content is user-authored, model-authored, tool-authored, retrieved, or external
* taint/untrusted state
* integrity metadata where available

Untrusted data must remain untrusted through transformations and agent handoffs unless an explicit trusted process changes that state.

### PolicyDecision

Provide a stable decision interface with outcomes such as:

* allow
* deny
* redact/transform
* require_approval

Include:

* decision ID
* policy ID
* policy version
* rule ID
* reason code
* human-readable explanation
* obligations/constraints
* timestamp
* expiry where applicable

Security decisions must be deterministic enough to test and audit.

### SecurityEvent

Generate a structured security record for consequential decisions and actions.

Include enough information to correlate:

identity
→ action
→ resource
→ policy decision
→ execution
→ result

with trace IDs and decision IDs.

Never record raw credentials or secrets merely to make the audit log complete.

## Ingestion security

Treat every ingestion channel as potentially hostile.

This includes:

* direct user prompts
* system/developer prompts loaded from configuration
* repository contents
* files
* uploaded documents
* MCP resources
* MCP tool results
* retrieved web content
* generated model output that will be re-consumed
* inter-agent messages
* persistent memory/context
* environment-derived information

Implement a consistent ingestion pipeline that supports:

1. schema validation
2. size/budget limits
3. normalization
4. source/provenance tracking
5. trust classification
6. sensitive-data classification where feasible
7. security-policy evaluation
8. structured audit/trace correlation

Do not strip provenance simply because content has been summarized or passed through an LLM.

Avoid pretending that regex alone solves prompt injection.

The existing string guardrail can remain as one inexpensive detector, but refactor it behind a detector/policy interface so stronger classifiers, DLP engines, external policy engines, or other security services can be added without changing the mediation architecture.

## Consumption and action security

All agent/model consumption of privileged data and all consequential actions should have enforceable control points.

For MCP/tool execution, move from:

tool_name → allow/deny

toward:

principal

* agent
* tool
* method
* structured arguments
* target resource
* destination
* data classification
* provenance
* session context
  → policy decision

The production enforcement path—not merely the adversarial lab—must enforce least privilege.

Where possible:

* authorize specific resources, not only tool names
* validate structured tool arguments
* reject path traversal
* canonicalize filesystem paths before policy evaluation
* prevent symlink-based boundary escapes
* constrain workspace scope
* distinguish reads from writes
* distinguish reversible from irreversible actions
* classify high-impact actions separately
* prevent credential forwarding unless explicitly authorized

Add explicit controls for outbound destinations.

An allowed tool must not imply arbitrary network egress.

Design for domain/service allowlists and policy-aware egress controls.

## Human approval

Create an interface for step-up approval of high-risk actions.

Examples:

* writes outside a safe scratch area
* destructive operations
* publishing/deployment
* git push
* credential use
* external communications
* actions that export sensitive information
* privilege elevation
* modifications to security configuration

Approval must bind to the exact proposed action.

The approval object should include or cryptographically bind:

* actor
* tool/action
* relevant arguments
* resource
* destination
* side effects
* policy decision
* expiration

Changing the action after approval must invalidate the approval.

Do not add fake UI merely to say human-in-the-loop exists. Build a clean backend contract even if the initial developer workflow is CLI/API based.

## Runtime containment

Assume application-layer policy eventually fails.

Harden containers and Compose configuration accordingly.

Review every service for:

* explicit non-root USER
* read-only root filesystem where feasible
* read-only mounts where feasible
* no-new-privileges
* dropped Linux capabilities
* seccomp/AppArmor compatibility
* tmpfs for required temporary writable locations
* CPU limits
* memory limits
* process/PID limits
* bounded open files if appropriate
* narrow network access
* health/readiness semantics
* safe restart behavior
* minimal packages
* removal of unnecessary shells/toolchains from runtime images

Pay particular attention to the Agentgateway runtime, because it currently combines gateway functionality with Node/npm/npx and MCP server execution.

Reduce blast radius without breaking MCP functionality.

The filesystem MCP's logical read-only policy should be reinforced by OS/filesystem permissions wherever practical.

Separate security boundaries when logical policy and runtime privileges currently disagree.

## Network exposure

Audit every published Docker port.

Internal services should not be host-accessible merely for convenience.

Prefer localhost binding where host access is genuinely necessary and internal-only Docker exposure otherwise.

Specifically review:

* guardrail service
* MCP endpoint
* LLM gateway
* OTLP receivers
* Jaeger
* code-server

Make architecture documentation match real runtime networking.

Add automated tests that detect accidental widening of host exposure.

Add a clear production deployment posture distinct from developer-local convenience where necessary.

## Identity and authentication

Design a real authenticated identity path for gateway decisions.

Do not rely forever on a single IDE password.

Support an architecture compatible with modern OIDC/OAuth/workload identity even if local development retains a simplified mode.

Ensure:

* authentication occurs before authorization
* user identity and workload/agent identity are distinguishable
* delegated authority is explicit
* credentials have narrow scopes
* credentials are not implicitly inherited by agents/tools
* issuer/audience/expiry checks are enforced where tokens are involved
* MCP authorization follows the current protocol specification
* confused-deputy conditions are tested

Separate IDE authentication credentials from privilege-elevation credentials.

Avoid persistent sudo access where it is unnecessary.

## Secrets and sensitive-data protection

Introduce a clean secret-handling model.

Review environment variables, logs, traces, error responses, model requests, tool arguments, tool responses, and test fixtures.

Implement redaction/suppression before telemetry export for known sensitive fields.

Ensure telemetry does not accidentally become a second exfiltration channel.

Never log:

* authorization headers
* API keys
* access tokens
* passwords
* private keys
* raw secrets

Add automated tests proving this.

Where possible, separate secret references/handles from raw secret values.

## Observability versus audit

Do not treat Jaeger traces as the authoritative security audit log.

Keep operational tracing, but introduce structured security-decision events.

Security events must contain enough context for forensic reconstruction without unnecessarily duplicating sensitive content.

Correlate security events and traces via IDs.

Document retention and integrity expectations.

## Rate limits, budgets and runaway-agent controls

Add interfaces and enforcement for:

* request rate
* concurrent model calls
* concurrent tool calls
* per-session tool-call budget
* maximum agent delegation depth
* maximum recursive action depth
* token/input limits
* token/output limits
* spend/cost budget where provider metadata permits
* action timeout
* overall workflow timeout
* circuit breaking

Fail safely when limits are exceeded.

Prevent denial-of-wallet and infinite loops.

## Failure semantics

For every security dependency, explicitly define behavior when it is:

* unavailable
* slow
* returns malformed data
* times out
* disagrees with another security component

Security-critical authorization must default to fail closed unless there is a carefully documented reason not to.

Availability-sensitive observability components should not necessarily take down unrelated safe operations.

Do not make all failures equivalent.

Test failure modes.

## Emergency/runtime controls

Create a path to:

* disable a model
* disable a tool
* disable an MCP server
* disable an agent/workload
* revoke a principal/session
* deny a destination
* stop a runaway workflow
* enter emergency deny mode

The architecture should permit these controls without rebuilding every container.

## Supply-chain security

Harden the repository and CI/CD.

At minimum:

* pin third-party GitHub Actions to immutable full commit SHAs
* use minimal workflow permissions
* make vulnerability scanning meaningful rather than informational-only where practical
* define thresholds/exceptions explicitly
* scan container images as well as filesystem dependencies
* generate SBOMs
* generate build provenance/attestations
* work toward SLSA 1.2-aligned provenance
* verify provenance/signatures before release or deployment where practical
* pin base images by digest where reasonable
* pin MCP/npm dependencies
* review `npx`/dynamic package execution risks
* prevent arbitrary dependency acquisition at runtime where feasible
* add dependency review
* detect secrets
* detect unsafe workflow changes
* separate untrusted pull-request execution from secrets

Do not introduce fragile security theater that makes dependency updates impossible. Make update procedures explicit and testable.

## Adversarial and security testing

Elevate the current swarm lab substantially.

Keep deterministic/keyless tests, but distinguish:

1. simulation tests
2. policy unit tests
3. gateway integration tests
4. actual MCP authorization tests
5. container isolation tests
6. end-to-end security regression tests

The current test runner's in-memory capability and delegation checks are useful demonstrations, but they must not be treated as proof of production enforcement.

Move important controls into real runtime enforcement and test them through the real gateway.

Add tests for at least:

* direct prompt injection
* indirect prompt injection
* obfuscated injection
* malicious tool output
* malicious MCP metadata
* capability escalation
* resource-scope bypass
* path traversal
* symlink traversal
* unauthorized write
* cross-agent delegation laundering
* confused deputy
* identity spoofing
* data exfiltration
* secret leakage into telemetry
* unsafe destination
* tool argument manipulation
* malformed guardrail response
* guardrail outage
* authorization outage
* excessively large requests
* excessive token requests
* recursive tool loop
* excessive delegation depth
* rate-limit exhaustion
* stale/expired approval
* modified action after approval
* unexpected code execution
* compromised/untrusted context persistence
* supply-chain configuration regressions

Use inert payloads for dangerous actions. Tests must never intentionally damage the host or exfiltrate real data.

Add fuzz/property tests where appropriate for parsers, normalization, resource canonicalization and policy decisions.

## Security invariants that CI must prove

Introduce machine-testable invariants such as:

* unauthorized tools are denied
* authorized tools cannot escape their resource scope
* unknown tools are denied
* unknown identities are denied for privileged operations
* identity cannot be supplied by an untrusted caller
* privileged actions require the correct policy decision
* approval is action-specific and expires
* untrusted provenance survives agent handoff
* secrets never appear in logs/traces
* policy service failure does not silently allow privileged operations
* externally inaccessible services remain unexposed
* containers run without unnecessary privilege
* dangerous tool execution cannot be achieved merely by prompt manipulation
* security events contain decision correlation IDs
* rate/depth/budget limits are enforced
* CI security scanners enforce documented thresholds

## Policy architecture

Do not hardcode the entire security model into Go conditionals.

Create a versionable policy layer.

It may use the existing CEL facilities where appropriate.

Prefer declarative policies for:

* actor
* action
* resource
* destination
* provenance/trust
* data classification
* environment

Policies should support:

* version identifiers
* deterministic tests
* default deny
* audit-only/shadow evaluation where useful
* staged rollout
* explicit exceptions with rationale
* rollback

Every production policy decision should expose which version/rule made the decision.

## Compatibility and scope control

Do not replace the entire stack merely because another product exists.

Use existing Loom architecture where it remains sound.

Prefer small, composable interfaces over a giant security service.

Avoid unnecessary dependencies.

Keep the developer quickstart functioning.

Do not add Kubernetes unless it is essential to implementing the security model.

Do not introduce a database purely for architectural aesthetics.

It is acceptable to implement clean interfaces and an in-memory/local-development backend first when external infrastructure would otherwise dominate the work, but the security semantics must be real and tested.

## Delivery approach

Work incrementally.

First, create:

`docs/security-threat-model.md`

and

`docs/security-roadmap.md`

The threat model must describe:

* assets
* actors
* trust boundaries
* ingress paths
* egress paths
* privileged actions
* abuse cases
* existing controls
* missing controls
* security invariants

Then produce a prioritized implementation plan.

Categorize changes:

P0 — exploitable architectural exposure / missing mandatory mediation
P1 — foundational security-control interfaces
P2 — defense in depth
P3 — advanced hardening/evaluation

Then begin implementation.

Do not stop after writing the plan.

Implement as much of P0 and P1 as reasonably possible in this task while keeping the repository in a working state.

For larger remaining items, create precise roadmap entries with proposed interfaces and acceptance criteria rather than vague TODOs.

## Important existing areas to inspect

Pay special attention to:

* `config/agentgateway-config.yaml`
* `docker/main.go`
* `docker-compose.yml`
* `docker/Dockerfile.gateway`
* `docker/Dockerfile.guardrail`
* `docker/swarm/`
* `.github/workflows/`
* `config/otel-collector-config.yaml`
* `tests/`
* `SECURITY.md`
* architecture ADRs

Validate documentation claims against runtime configuration.

Fix drift.

## Definition of done

A successful result is not "we added security documentation."

At the end:

1. Existing tests pass.
2. New security tests pass.
3. The quickstart remains usable.
4. The production security model is stronger than the lab-only model.
5. Authorization can incorporate identity and resource context.
6. Tool arguments/resources can be evaluated before execution.
7. Untrusted-data provenance has a representation.
8. Security decisions have durable IDs and structured reasons.
9. Security events correlate with traces without leaking secrets.
10. Internal services have appropriately reduced exposure.
11. Container privilege has materially decreased.
12. CI supply-chain controls are stronger.
13. Rate/depth/budget interfaces exist and are enforced for relevant paths.
14. Failure behavior for security dependencies is tested.
15. The swarm lab exercises real production enforcement wherever possible.
16. There is a documented mapping from implemented controls to the relevant OWASP Agentic/LLM threat categories.
17. No documentation claims a control exists unless the repository actually enforces and tests it.

## Output at completion

Provide:

1. A concise architecture/security assessment of the original repository.
2. A list of security invariants adopted.
3. A summary of files changed.
4. A description of each new enforcement interface.
5. Threats mitigated by each change.
6. Threats intentionally not yet mitigated.
7. Tests added and exactly what they prove.
8. Remaining P0/P1 gaps, if any.
9. Instructions for running all security tests locally.
10. Any breaking changes or migration instructions.

Be skeptical of your own changes.

Before finishing, perform a second-pass adversarial review asking:

"If the model, user input, retrieved content, MCP server, tool response, workspace, or one container were malicious, which trust boundaries could still be crossed?"

Fix material findings you discover before concluding.
