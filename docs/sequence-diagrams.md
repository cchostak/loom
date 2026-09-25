# Loom Security Architecture — Sequence Diagrams

This document illustrates the operational sequences across Loom's security boundaries, detailing both **happy flows** (authorized, inspected execution) and **unhappy flows** (denials, tampering, quota limits, circuit breaks, and attack mitigations).

- [1. AI Model Inference Mediation](#1-ai-model-inference-mediation)
- [2. Model Context Protocol (MCP) Tool Execution & Cryptographic Sealing](#2-model-context-protocol-mcp-tool-execution--cryptographic-sealing)
- [3. Zero-Trust Workload Identity (SPIFFE/SPIRE & mTLS A2A)](#3-zero-trust-workload-identity-spiffespire--mtls-a2a)
- [4. Telemetry Normalization & Unified Compliance Evidence Queue](#4-telemetry-normalization--unified-compliance-evidence-queue)
- [5. Multi-Agent Swarm Orchestration, Least Privilege & Lineage Handoff](#5-multi-agent-swarm-orchestration-least-privilege--lineage-handoff)
- [Summary Defense Matrix](#summary-defense-matrix)

---

## 1. AI Model Inference Mediation

Mediation flow for user and agent model completion requests through authentication, versioned policy, session budgets, circuit breaker, content guardrails, and audit logging.

```mermaid
sequenceDiagram
    autonumber
    actor Client as Client / Agent / IDE
    participant Boundary as Boundary Server<br/>(boundary.Server)
    participant Auth as Authenticator<br/>(Registry / OIDC / SVID)
    participant Policy as Policy Engine<br/>(security.Policy)
    participant Budget as Budget Controller<br/>(security.Budgets)
    participant Circuit as Circuit Breaker<br/>(security.Circuit)
    participant Guard as Guardrail Proxy<br/>(PII & Content Guard)
    participant Upstream as Agentgateway / LLM
    participant Audit as Audit & Telemetry<br/>(Audit & OTLP)

    Client->>Boundary: POST /v1/chat/completions (Bearer Token / mTLS SVID)
    alt Unhappy: Unauthenticated / Invalid Credential
        Boundary->>Auth: Authenticate(r)
        Auth-->>Boundary: error (invalid / expired / unknown)
        Boundary-->>Client: 401 Unauthorized (WWW-Authenticate: Bearer)
    else Happy: Authenticated Identity
        Boundary->>Auth: Authenticate(r)
        Auth-->>Boundary: IdentityContext (Principal, Workload, Tenant, Session)
        Boundary->>Policy: Evaluate(ActionRequest)
        alt Unhappy: Policy Denial (Forbidden Model / Workload Mismatch)
            Policy-->>Boundary: PolicyDecision (Outcome: "deny", Reason: "forbidden_model")
            Boundary-->>Client: 403 Forbidden ("Policy denied: forbidden_model")
        else Policy Allowed
            Boundary->>Budget: AcquireFor(ControlContext, BudgetKey, tokens)
            alt Unhappy: Budget Exceeded (RPM / Tokens / Concurrency)
                Budget->>Audit: Emit ControlEvent ("budget", "admission_limit")
                Budget-->>Boundary: error ("budget exceeded")
                Boundary-->>Client: 429 Too Many Requests ("budget_exceeded")
            else Budget Admitted
                Boundary->>Circuit: AllowFor(ControlContext, now)
                alt Unhappy: Circuit Breaker Open (Upstream Outage)
                    Circuit->>Audit: Emit ControlEvent ("circuit", "dispatch_blocked")
                    Boundary-->>Client: 503 Service Unavailable ("circuit_open")
                else Circuit Healthy (Closed)
                    Boundary->>Guard: POST /validate (inspect prompt)
                    alt Unhappy: Input Guardrail Triggered (PII / Injection Pattern)
                        Guard-->>Boundary: ValidationResponse (Status: "rejected")
                        Boundary-->>Client: 403 Forbidden ("Input inspection denied")
                    else Prompt Clean
                        Boundary->>Upstream: POST /v1/chat/completions (Normalized Body, Trace Headers)
                        alt Unhappy: Upstream Network / Timeout Failure
                            Upstream-->>Boundary: Connection error / 502
                            Boundary->>Circuit: CompleteFor(ctx, success: false)
                            Note over Circuit: 3 consecutive failures trip circuit to OPEN (30s cooldown)
                            Boundary-->>Client: 502 Bad Gateway ("Upstream unavailable")
                        else Upstream 200 OK
                            Upstream-->>Boundary: 200 OK + Raw Completion JSON
                            Boundary->>Circuit: CompleteFor(ctx, success: true)
                            Boundary->>Guard: POST /validate (inspect completion output)
                            alt Unhappy: Output Inspection Denied (PII / Secret Leak)
                                Guard-->>Boundary: ValidationResponse (Status: "rejected")
                                Boundary-->>Client: 403 Forbidden ("Output inspection denied")
                            else Output Safe
                                Guard-->>Boundary: ValidationResponse (Status: "allowed")
                                Boundary->>Audit: Record result (200, "result")
                                Boundary-->>Client: 200 OK + Filtered JSON + Trace Headers
                            end
                        end
                    end
                end
            end
        end
    end
```

---

## 2. Model Context Protocol (MCP) Tool Execution & Cryptographic Sealing

MCP tool discovery, offline signed tool contracts, schema validation, prompt injection sanitization, safe filesystem sandboxing, and response cryptographic sealing.

```mermaid
sequenceDiagram
    autonumber
    actor Agent as Strands Agent Worker
    participant Interceptor as MCP Interceptor<br/>(MCPInterceptorMiddleware)
    participant Boundary as Boundary Server<br/>(/mcp endpoint)
    participant SafeFS as SafeFS Stdio Server<br/>(O_NOFOLLOW Sandboxed)
    participant Guard as Guardrail Proxy<br/>(/validate)
    participant Signer as MCP Signer<br/>(Ed25519 Key)

    Note over Agent,Interceptor: Phase 1: Tool Discovery & Poisoning Prevention
    Agent->>Interceptor: Request tools list ("tools/list")
    Interceptor->>Boundary: POST /mcp ("tools/list")
    Boundary->>SafeFS: JSON-RPC tools/list
    SafeFS-->>Boundary: Available tool schemas
    Boundary-->>Interceptor: JSON-RPC Response (tools array)
    alt Unhappy: Tool Poisoning / Mutated Schema
        Note over Interceptor: Validates against signed tool_contract.json & TOOL_DEFINITION_SCHEMA
        Interceptor-->>Agent: Terminate exchange (LoomFailure: "Tool poisoning / schema mismatch")
    else Happy: Tool Definitions Match Signed Contract
        Interceptor-->>Agent: Approved tools (read_text_file, list_directory)
    end

    Note over Agent,Interceptor: Phase 2: Tool Execution, Traversal Defense & Sealing
    Agent->>Interceptor: Invoke tool ("tools/call", args: {path: "/workspace/report.txt"})
    alt Unhappy: Path Traversal Attack ("../", backslashes, control characters)
        Interceptor-->>Agent: Reject call (LoomFailure: "MCP resource denied")
    else Happy: Valid Canonical Path
        Interceptor->>Boundary: POST /mcp (JSON-RPC call, session token)
        alt Unhappy: Session Hijacking Attempt
            Boundary-->>Interceptor: 403 Forbidden ("session_mismatch")
        else Authorized Session
            Boundary->>SafeFS: Execute tool call
            alt Unhappy: Symlink / Boundary Escape
                SafeFS-->>Boundary: Error ("Tool denied" via O_NOFOLLOW)
            else Legitimate File Read
                SafeFS-->>Boundary: File content (< 64 KiB)
            end
            Boundary->>Guard: POST /validate (inspect output text)
            Guard-->>Boundary: Allowed
            Boundary->>Signer: SealMCP(Ed25519Key, reqBody, respBody, session, trace)
            Signer-->>Boundary: Headers: X-Loom-MCP-Signature, X-Loom-MCP-Issued
            Boundary-->>Interceptor: 200 OK + MCP Result + Signature Headers
            alt Unhappy: Response Tampered or Stale (> 45s)
                Interceptor-->>Agent: Terminate exchange (LoomFailure: "MCP response auth failed")
            else Cryptographically Authentic Response
                alt Unhappy: Contains Raw Control Characters
                    Interceptor-->>Agent: Terminate exchange (LoomFailure: "control characters")
                else Clean Payload: Neutralize Delimiters
                    Interceptor->>Interceptor: Delimiters -> [SANITIZED_INJECTION_MARKER]
                    Interceptor-->>Agent: Safe tool output + DataContext(tainted: true)
                end
            end
        end
    end
```

---

## 3. Zero-Trust Workload Identity (SPIFFE/SPIRE & mTLS A2A)

Multi-agent swarms and backend containers establish cryptographic identity using short-lived SPIFFE Verifiable Identity Documents (SVIDs) and mutual TLS.

```mermaid
sequenceDiagram
    autonumber
    participant Workload as Agent / Boundary Container<br/>(e.g. strands-researcher)
    participant SPIREAgent as SPIRE Agent<br/>(/run/spire/agent.sock)
    participant DockerRelay as Docker Metadata Relay<br/>(docker-metadata)
    participant SPIREServer as SPIRE Server CA<br/>(spire-server)
    participant Peer as Boundary / Upstream Peer<br/>(control-plane / guardrail-proxy)

    Note over Workload,SPIREServer: 1. Workload Attestation & SVID Minting
    Workload->>SPIREAgent: Connect unix:///run/spire/agent.sock (FetchX509SVID)
    SPIREAgent->>DockerRelay: Inspect caller process PID / container labels
    DockerRelay-->>SPIREAgent: Verified labels (service: strands-researcher, project: loom)
    SPIREAgent->>SPIREServer: Request SVID for spiffe://loom.local/workload/strands-researcher
    SPIREServer-->>SPIREAgent: Short-Lived X.509 SVID (TTL: 5m, Max 10m) + Trust Bundle
    SPIREAgent-->>Workload: SVID + Private Key + Trust Bundle

    Note over Workload,Peer: 2. Agent-to-Agent (A2A) / Container mTLS Handshake
    Workload->>Peer: Initiate TLS 1.3 mTLS Connection (Present Client SVID)
    alt Unhappy: Plaintext / Non-mTLS Request Attempt
        Peer-->>Workload: 401 Unauthorized ("mTLS required")
    else mTLS Handshake Initiated
        Workload-->>Peer: Client SVID Certificate
        alt Unhappy: Lifetime Exceeds Policy (> 10m) or Expired
            Peer-->>Workload: 401/403 ("SVID lifetime exceeds policy" / "SVID expired")
        else Valid Short-Lived Certificate
            alt Unhappy: Unauthorized Peer / Rogue Workload ID
                Peer-->>Workload: 403 Forbidden ("SPIFFE peer denied")
            else Happy: Authorized Peer Identity
                alt Direct SVID Authentication (Pure A2A)
                    Peer->>Peer: Map SPIFFE ID -> IdentityContext ("spiffe-svid-mtls")
                    Peer-->>Workload: 200 OK (Cryptographically authenticated)
                else Bound SVID + Bearer Token Authentication
                    Peer->>Peer: Verify Bearer token claims against SVID URI binding
                    Peer-->>Workload: 200 OK (or 403 on identity mismatch)
                end
            end
        end
    end
```

---

## 4. Telemetry Normalization & Unified Compliance Evidence Queue

Guardrail trigger events (budget limits, circuit breaker trips) converted to OpenTelemetry log records, transformed by OTel Collector, normalized into the BlackShield Unified Finding schema, and stored in the SQLite compliance queue.

```mermaid
sequenceDiagram
    autonumber
    participant Guardrail as Security Guardrail<br/>(budget.go / circuit.go)
    participant OTLPClient as OTLP Log Sink<br/>(security.OTLPEvents)
    participant OTelCol as OTel Collector Contrib<br/>(:4319 / :4318)
    participant Normalizer as Normalizer Service<br/>(enterprise.Normalizer)
    participant Queue as SQLite Store<br/>(normalization_queue)
    actor Auditor as Compliance Auditor / SIEM

    Note over Guardrail,OTLPClient: 1. Guardrail Breach: Emit ControlEvent(budget/circuit, SHA256 digest)
    Guardrail->>OTLPClient: Emit(ControlEvent: Kind="budget", Reason="admission_limit", Resource=digest)
    Note over OTLPClient,OTelCol: 2. Asynchronous Bounded Export
    OTLPClient->>OTelCol: POST http://otel-collector:4319/v1/logs (Bearer token)
    Note over OTelCol,Normalizer: 3. Telemetry Governance: transform/governance restricts attributes
    OTelCol->>Normalizer: POST http://normalizer:8080/v1/logs (otlp_http/normalizer)
    Note over Normalizer,Queue: 4. Unified Schema Normalization & Storage
    alt Unhappy: Malformed Attributes (regex hexID, digestID fail)
        Normalizer-->>OTelCol: 400 Bad Request ("invalid evidence")
    else Happy: Map to UnifiedFinding & Store
        Normalizer->>Queue: INSERT INTO normalization_queue
        alt Queue Full (> 100,000 records)
            Normalizer-->>OTelCol: 503 Service Unavailable ("queue capacity")
        else Queued Successfully
            Normalizer-->>OTelCol: 200 OK ({})
        end
    end
    Note over Auditor,Normalizer: 5. Audit Evidence Retrieval
    Auditor->>Normalizer: GET /findings (Bearer token)
    alt Unauthorized Audit Access
        Normalizer-->>Auditor: 403 Forbidden ("denied")
    else Authorized Auditor Query
        Normalizer->>Queue: SELECT finding FROM normalization_queue LIMIT 100
        Normalizer-->>Auditor: 200 OK (UnifiedFinding list)
    end
```

---

## 5. Multi-Agent Swarm Orchestration, Least Privilege & Lineage Handoff

Swarm roles (Researcher, Planner, Operator, Publisher) collaborate under least privilege, immutable data taint tracking, and turn boundaries.

```mermaid
sequenceDiagram
    autonumber
    actor User as User / Host Runner
    participant Researcher as Agent: Researcher<br/>(strands-researcher)
    participant Planner as Agent: Planner<br/>(strands-planner)
    participant Operator as Agent: Operator<br/>(strands-operator)
    participant Publisher as Agent: Publisher<br/>(strands-publisher)
    participant ControlPlane as Control Plane<br/>(Policy & Boundary)

    User->>Researcher: Start Task (User prompt)
    Note over Researcher: Allowed: read_text_file | Denied: list_directory, writes, models
    Researcher->>ControlPlane: POST /mcp (read_text_file "/workspace/data.txt")
    ControlPlane-->>Researcher: File content (Wrapped in DataContext(trust="untrusted", tainted=true))
    Researcher->>Planner: Handoff Proposal (Context JSON with lineage parents)
    Note over Planner: Allowed: LLM reasoning | Denied: ALL filesystem tools
    alt Unhappy: Privilege Escalation Attempt
        Planner->>ControlPlane: POST /mcp (read_text_file "/workspace/secret.key")
        ControlPlane-->>Planner: 403 Forbidden ("Policy denied: tool_not_granted")
    end
    Planner->>Operator: Handoff Execution Plan (Preserving taint lineage)
    Note over Operator: Allowed: list_directory | Denied: read_text_file, writes
    Operator->>ControlPlane: POST /mcp (list_directory "/workspace")
    ControlPlane-->>Operator: 200 OK (Directory entries)
    Operator->>Publisher: Handoff Results Summary
    Note over Publisher: Allowed: model synthesis | Denied: external network export, filesystem
    alt Unhappy: Taint Cleansing / Lineage Forgery Attempt
        Publisher->>Publisher: Attempt to set DataContext(tainted=false, trust="trusted")
        Note over Publisher: Control plane re-evaluates all incoming data as untrusted.<br/>Local assertions cannot elevate authority.
    end
    Publisher->>User: Formatted Final Report (with immutable provenance trail)
```

---

## Summary Defense Matrix

| Boundary / Layer | Happy Path Guarantee | Unhappy Path Defense | Enforcing Component |
| :--- | :--- | :--- | :--- |
| **Authentication** | Valid token/SVID resolves to verified `IdentityContext` | Missing/expired/tampered credentials fail closed with 401 | `Registry`, `OIDC`, `WorkloadAuth` |
| **Policy** | Explicit versioned allow rules match principal & tool | Default-deny on all ungranted models, tools, or resources (403) | `security.Policy` |
| **Execution Budgets** | Admitted operations tracked against session limits | 429 Too Many Requests on RPM, token, call, or concurrency breach | `security.Budgets` |
| **Circuit Breakers** | Fast passthrough during healthy upstream operation | 503 Service Unavailable when 3 upstream failures occur (30s cooldown) | `security.Circuit` |
| **Content Inspection** | Clean prompts and completions pass with correlation headers | 403 on PII detection or disallowed destructive/injection commands | `guardrail-proxy`, `pii.Scrubber` |
| **MCP Validation** | Offline signed tool contracts execute with validated schema | Rejection on schema mutation, tool poisoning, or prompt injection | `MCPInterceptorMiddleware` |
| **Filesystem (SafeFS)** | Regular file reads constrained under `/workspace` | `O_NOFOLLOW` descriptor-relative resolution blocks traversal & symlinks | `docker/safefs/` |
| **Zero-Trust Identity** | Short-lived SVIDs (< 10m) enable cryptographic mTLS A2A | Non-mTLS, expired certs, or unlisted SPIFFE IDs rejected | SPIFFE/SPIRE, `SVIDMiddleware` |
| **Audit & Governance** | OTel events normalized into unified compliance finding schema | Tampered telemetry rejected (400), audit queue bounded at 100k (503) | `OTelCollector`, `Normalizer` |
