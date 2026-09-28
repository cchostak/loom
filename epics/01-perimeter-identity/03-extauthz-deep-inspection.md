# TASK-PI-03: External Authorization (ExtAuthz) Protocol for Deep Payload Validation

## Epic: 01-perimeter-identity
**Status**: Ready for Implementation  
**Security Classification**: High (Pre-execution Policy Authorization)  
**Relevant Standards**: Envoy External Authorization v3 API (`envoy.service.auth.v3`), gRPC Core, JSON Schema Draft 7  

---

## 1. Context & Tooling Evaluation

Offloading edge authentication (JWT verification, rate limiting) to API gateways is efficient, but gateways are not suited for deep application-level cryptographic verification, recursive JSON schema inspection, or LLM-specific jailbreak detection. We must evaluate patterns for delegating deep validation out-of-band before requests reach backend tool engines.

### Tooling Trade-Off Matrix

| Authorization Pattern | Enterprise Fit | Pros | Cons / Constraints | Selection Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| **Envoy v3 gRPC ExtAuthz (`envoy.service.auth.v3`)** | High (Industry Standard) | High throughput, binary protobuf serialization, standardized check/allow/deny semantics, header mutation support. | Requires gRPC service implementation; body buffering must be configured explicitly. | **Selected Standard**: Universally supported by Envoy, AgentGateway, Istio, and modern cloud API gateways. |
| **HTTP Webhook / ForwardAuth** | Medium (Universal HTTP) | Simple HTTP request/response model; easy to write in any language. | JSON serialization overhead, increased latency, inconsistent header mutation conventions across gateway vendors. | **Fallback**: Use only if gRPC transport is restricted by network policies. |
| **In-Process Wasm / Lua Filters** | Medium (Edge Execution) | Zero network hop; executed directly inside gateway worker threads. | Sandboxed memory constraints, complex debugging for cryptographic signature checks; crash risks to gateway. | **Not Recommended for Crypto**: Complex Ed25519 signing and large schema validators are better isolated in dedicated microservices. |

---

## 2. Problem Statement & Threat Vectors

Even when an incoming request carries a valid corporate JWT and passes rate limiting, the JSON-RPC payload may contain destructive parameters, unauthorized capabilities, directory traversal strings (`../../etc/passwd`), or prompt injection delimiters. Validating these complex semantic constraints within the edge gateway directly would bloat gateway configuration and reduce edge throughput.

### Threat Vectors
- **Parameter Tampering & Path Traversal (OWASP LLM08 / CWE-22)**: Exploiting filesystem tools with malformed path arguments.
- **Prompt Injection in Tool Parameters (OWASP LLM01)**: Embedding system prompt override delimiters in user-supplied tool inputs.
- **Unauthorized Tool Capabilities (CWE-285)**: Calling internal or administrative tool functions not exposed in the authenticated user's session contract.

---

## 3. Architecture & Technical Blueprint

```text
API Security Gateway (Edge Perimeter)
        │
        ├── 1. Edge Checks Pass: JWT Validated + Token Budget Checked + Rate Limit OK
        │
        ▼ 2. gRPC CheckRequest (Buffered JSON-RPC payload & headers)
ExtAuthz Dedicated Microservice (:9001)
        │
        ├── 3. Cryptographic Verification: Verify publisher signature on tool contract
        ├── 4. Capability Authorization: Verify requested tool exists in contract allowlist
        ├── 5. Deep JSON Schema Validation: Enforce parameter types and additionalProperties: false
        ├── 6. Path Traversal Inspection: Reject '..', '\', control chars, paths outside /workspace
        ├── 7. Prompt Injection Inspection: Reject '[SYSTEM]', special tokens, override phrases
        │
        ▼ 8. CheckResponse_OkResponse + Header Mutations:
             - X-Loom-MCP-Validated: true
             - X-Loom-MCP-Signature: <hex-attestation-signature>
Gateway Edge
        │
        ▼ 9. Forward Request + Injected Attestation Headers to Backend Tool Server
Backend Tool Server (safefs / container worker)
        │
        └── 10. Validates attestation header before executing system operations
```

---

## 4. Implementation Tasks

- [ ] Implement Envoy `envoy.service.auth.v3.AuthorizationServer` gRPC interface in a dedicated security service.
- [ ] Configure gateway `extAuthz` client with request body buffering (`packAsBytes: true`, `maxRequestBytes: 65536`).
- [ ] Implement tool contract capability allowlist evaluation.
- [ ] Implement recursive JSON Schema argument validation with strict rejection of undeclared properties.
- [ ] Implement input sanitization rules blocking directory traversal and prompt injection markers.
- [ ] Implement cryptographic attestation header injection (`X-Loom-MCP-Validated`, `X-Loom-MCP-Signature`).
- [ ] Implement comprehensive test harness covering capability denials, schema errors, traversal attacks, and valid flows.

---

## 5. Definition of Done (DoD) & Acceptance Criteria

1. **Protocol Compliance**: ExtAuthz service correctly implements `envoy.service.auth.v3` Check API and responds within $\le 5$ms.
2. **Deterministic Denial**: Malicious payloads (traversal, injections, undeclared properties) are rejected with `403 Forbidden` (`PERMISSION_DENIED`).
3. **Attestation Injection**: Valid payloads receive signed attestation headers that backend tools can verify independently.
4. **Resilience & Fail-Closed**: If the ExtAuthz service is unreachable, the gateway fails closed, preventing uninspected execution.
5. **Automated Unit & Integration Tests**: Complete test suite passes with full branch coverage on security checks.

---

## 6. Verification & Validation Strategy

```bash
# Verify ExtAuthz gRPC Check handler against malformed and attack payloads
cd docker && go test -v -race -run TestExtAuthz ./security
```
