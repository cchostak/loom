# Enterprise AI Security Implementation Tasks

This document contains actionable, production-ready tasks for implementing enterprise AI security controls across AI gateways, Model Context Protocol (MCP) tool interfaces, workload identity, and telemetry governance.

---

### Task Index
1. [TASK-01: MCP Context Layer & Strict Schema Validation](#task-01-mcp-context-layer--strict-schema-validation)
2. [TASK-02: Zero-Trust SPIFFE/SPIRE Workload Identity & mTLS](#task-02-zero-trust-spiffespire-workload-identity--mtls)
3. [TASK-03: Telemetry Normalization & Unified Compliance Evidence Queue](#task-03-telemetry-normalization--unified-compliance-evidence-queue)
4. [TASK-04: Distributed Quota Accounting & Circuit Breakers](#task-04-distributed-quota-accounting--circuit-breakers)
5. [TASK-05: Document-Level Vector Security (DLS) & Ingestion Poisoning Defense](#task-05-document-level-vector-security-dls--ingestion-poisoning-defense)
6. [TASK-06: Multi-Stage Semantic Guardrails & Automated Red Teaming](#task-06-multi-stage-semantic-guardrails--automated-red-teaming)

---

### TASK-01: MCP Context Layer & Strict Schema Validation

#### Description
Model Context Protocol (MCP) servers expose tools and filesystem endpoints to LLMs. Without strict validation, untrusted data payloads and poisoned tool schemas can hijack agent execution (OWASP LLM01, LLM08). Implement an interceptor middleware that cryptographically signs tool contracts, validates incoming tool schemas against strict JSON schemas, neutralizes prompt injection delimiters, and strips non-printable control characters.

#### Implementation Blueprint
- Define immutable tool contract (`tool_contract.json`) signed with an offline Ed25519 private key.
- Deploy `MCPInterceptorMiddleware` in the agent transport layer:
  - `validate_request()`: Enforce JSON-RPC structure and block path traversal (`../`, `\`, control chars).
  - `validate_tools()`: Verify tool schemas against `TOOL_DEFINITION_SCHEMA`; detect injected prompts in descriptions.
  - `sanitize_data_payload()`: Neutralize `<|...|>`, `[SYSTEM]`, ```` delimiters into `[SANITIZED_INJECTION_MARKER]`.
  - `verify_response()`: Cryptographically verify `X-Loom-MCP-Signature` with public Ed25519 key within 45s TTL.
- Pair with `safefs` using kernel-level descriptor-relative resolution (`O_NOFOLLOW`) for filesystem tool sandboxing.

#### Definition of Done (DoD)
- [ ] Tool contract signatures verified using Ed25519 public key before tool registration.
- [ ] Altering tool schema or adding unlisted tools halts exchange with `LoomFailure("Tool poisoning / schema mismatch")`.
- [ ] Path traversal payloads (`../../etc/passwd`) are rejected with `LoomFailure("MCP resource denied")`.
- [ ] Tool payloads containing injection markers are rewritten with immutable taint tracking (`tainted=true`).
- [ ] Automated unit test suite passes: `make mcp-test`.

---

### TASK-02: Zero-Trust SPIFFE/SPIRE Workload Identity & mTLS

#### Description
Static API keys in configuration files are vulnerable to lateral movement and leakage. Implement zero-trust cryptographic workload identity for all Agent-to-Agent (A2A) and container-to-container communication using SPIFFE/SPIRE with short-lived X.509 SVIDs ($\le$ 10m) and mTLS.

#### Implementation Blueprint
- Deploy SPIRE Server and Agent in the container orchestration plane:
  - Mount SPIRE workload API socket at `unix:///run/spire/agent.sock`.
  - Use Docker metadata relay to attest caller container labels (`project=loom`, `service=<name>`).
- Implement `WorkloadAuth` and `SVIDMiddleware` on all boundary services:
  - Require TLS 1.3 with client certificate (`PeerCertificates[0]`).
  - Validate SVID validity duration ($NotAfter - NotBefore \le 10\text{m}$) and enforce clock-skew validity.
  - Parse URI SAN (`spiffe://<domain>/workload/<id>`) and verify against `WorkloadConfig.Peers` ACL.
  - Bind bearer token claims to attested SVID URI identity to prevent credential theft.

#### Definition of Done (DoD)
- [ ] SPIRE Server issues X.509 SVIDs with TTL $\le$ 10 minutes to attested agent containers.
- [ ] Plaintext/non-mTLS requests to internal boundaries receive `401 Unauthorized ("mTLS required")`.
- [ ] SVID certificates with lifetimes exceeding 10 minutes receive `403 Forbidden ("SVID lifetime exceeds policy")`.
- [ ] Unlisted SPIFFE IDs are denied with `403 Forbidden ("SPIFFE peer denied")`.
- [ ] Go workload identity unit test suite passes: `cd docker && go test -v -run 'TestWorkload|TestSVID' ./security`.

---

### TASK-03: Telemetry Normalization & Unified Compliance Evidence Queue

#### Description
Guardrail triggers and security policy events must be collected, scrubbed of PII/secrets, and normalized into an enterprise SIEM-compatible schema to satisfy SOC 2, ISO 27001, and EU AI Act audit requirements.

#### Implementation Blueprint
- Emit structured `ControlEvent` on budget limit hits (`admission_limit`) and circuit trips (`dispatch_blocked`).
  - Hash resource identifiers to 64-char SHA-256 digests; generate unique 32-char hex Event IDs.
- Deploy OpenTelemetry Collector with `transform/governance` processor:
  - Whitelist attributes: `loom.event_id`, `loom.kind`, `loom.reason`, `loom.resource`, `loom.tenant`, `loom.trace_id`.
  - Route logs via `otlp_http/normalizer` to the Normalizer service.
- Implement Normalizer service mapping events to BlackShield `UnifiedFinding` format:
  - Budget breach $\rightarrow$ `finding_type: "policy_violation"`, Circuit trip $\rightarrow$ `finding_type: "posture_drift"`.
  - Store deduplicated findings in SQLite/Postgres `normalization_queue` with 100k bounded capacity.
  - Expose authenticated `GET /findings` endpoint for SIEM scrapers.

#### Definition of Done (DoD)
- [ ] Budget and circuit breaker triggers emit OTel log records with SHA-256 sanitized resources.
- [ ] OTel collector governance filter strips unapproved attributes and forwards clean events.
- [ ] Normalizer correctly validates attributes (regex hexID, digestID) and converts records into UnifiedFinding JSON.
- [ ] `GET /findings` returns valid findings array for authorized auditors and `403 Forbidden` otherwise.
- [ ] Automated normalization tests pass: `make test-telemetry`.

---

### TASK-04: Distributed Quota Accounting & Circuit Breakers

#### Description
Multi-agent swarms can enter recursive execution loops or execute high-volume downstream model calls, resulting in denial of wallet or provider API exhaustion. Implement shared transaction-safe admission budgets and automated circuit breakers.

#### Implementation Blueprint
- Implement transactional token bucket and sliding-window rate limiters:
  - Per-session limits: Requests Per Minute (RPM), admitted operations, concurrent calls, and workflow timeout.
  - Isolate budget keys by tenant and workload (`TenantContext`).
- Implement circuit breaker on upstream model providers and tool endpoints:
  - Track consecutive upstream failures (5xx, timeouts, connection errors).
  - Trip circuit to `OPEN` after 3 consecutive failures; fail fast with `503 Service Unavailable` for 30s cooldown.
  - Transition to `HALF-OPEN` to test upstream recovery before resuming normal dispatch.

#### Definition of Done (DoD)
- [ ] Exceeding concurrent call or RPM limits immediately returns `429 Too Many Requests`.
- [ ] Consecutive upstream 502/timeout responses trip the circuit and block new dispatches for 30 seconds.
- [ ] Circuit breaker events emit structured `ControlEvent` telemetry records.
- [ ] Budget unit tests pass: `cd docker && go test -v -run TestBudget ./security`.

---

### TASK-05: Document-Level Vector Security (DLS) & Ingestion Poisoning Defense

#### Description
In enterprise RAG architectures, querying vector embeddings across shared indices can leak confidential data across organizational boundaries. Ingested third-party documents can also contain indirect prompt injections.

#### Implementation Blueprint
- Implement Document-Level Security (DLS) pre-filtering:
  - Store tenant ID, user role, and document ACLs in vector metadata.
  - Inject tenant filter into every vector query *prior* to similarity calculation.
- Implement Ingestion Pipeline Hygiene:
  - Scrape and extract text in isolated runner containers (gVisor).
  - Scan ingested documents for hidden instructions, zero-width characters, and base64 injection payloads.
  - Mark unvetted documents as untrusted in document lineage graphs.

#### Definition of Done (DoD)
- [ ] Vector similarity search guarantees zero cross-tenant chunk retrieval.
- [ ] Ingested test documents containing injection phrases are quarantined prior to embedding generation.
- [ ] Document access rechecks live user permissions on every read query.

---

### TASK-06: Multi-Stage Semantic Guardrails & Automated Red Teaming

#### Description
Regex string heuristics can be bypassed by cipher encoding, multilingual prompts, and jailbreaks. Implement defense-in-depth guardrail ensembles and continuous red-teaming harnesses.

#### Implementation Blueprint
- Implement a two-tier guardrail pipeline:
  - **Tier 1 (Fast Deterministic)**: Heuristic pattern checks, Presidio PII detector, and entropy analysis.
  - **Tier 2 (Semantic Classifier)**: Small dedicated guardrail models (e.g. Llama Guard, NeMo) classifying inputs.
- Establish an automated adversarial evaluation harness:
  - Run benchmark attacks (Garak, PyRIT) against the boundary in CI/CD pipelines.
  - Measure bypass rate; gate releases on zero high-severity jailbreak regressions.

#### Definition of Done (DoD)
- [ ] High-risk prompts (harmful categories, injection attempts) blocked with `403 Forbidden`.
- [ ] PII entities (SSN, credit card, email, phone) scrubbed or rejected according to tenant policy.
- [ ] CI/CD pipeline runs automated adversarial suite: `make lab` and `make lab-json`.
