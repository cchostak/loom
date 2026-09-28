# TASK-MC-02: Strict Schema Enforcement & Parameter Sanitization for MCP Tools

## Epic: 02-mcp-tool-containment
**Status**: Ready for Implementation  
**Security Classification**: High (Input Validation & Protocol Integrity)  
**Relevant Standards**: JSON Schema Draft 7 / Draft 2020-12, Model Context Protocol Specification, OWASP Top 10 for LLM (LLM08)  

---

## 1. Context & Tooling Evaluation

Model Context Protocol (MCP) clients and servers communicate via JSON-RPC. Because LLMs hallucinate arguments and adversaries can inject unexpected parameter keys, the authorization layer must strictly enforce schema constraints before passing arguments to backend tool executors.

### Tooling Trade-Off Matrix

| Schema Validation Technology | Enterprise Fit | Pros | Cons / Constraints | Selection Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| **JSON Schema (Draft 7 / 2020-12)** | High (Native MCP Standard) | Native format for MCP tool definitions, language-agnostic, supported across Go, Python, and C++, enforces `additionalProperties: false`. | Validation libraries vary in Draft support; regex keyword evaluation can introduce ReDoS if unconstrained. | **Selected Standard**: Primary protocol definition format for MCP tool contracts and gateway validation. |
| **Pydantic (Python) / Zod (TypeScript)** | Medium (Application Level) | Rich type validation, developer ergonomic in application code. | Language-bound; cannot be shared directly with Go/Envoy authorization proxies without duplicate definitions. | **Supplemental**: Use in Python/TS tool implementations as a secondary defense layer. |
| **Protocol Buffers (Protobuf v3)** | High (Binary Performance) | Binary serialization, compile-time type safety, zero ambiguity in field types. | Requires recompiling schemas for every tool addition; incompatible with dynamic MCP discovery endpoints. | **Internal Transit Only**: Use for gRPC ExtAuthz transport; wrap tool JSON in protobuf bytes. |

---

## 2. Problem Statement & Threat Vectors

LLMs often append unexpected fields, mutate primitive types (e.g. sending strings where booleans are required), or inject hidden parameters designed to override application settings in underlying command-line tools. Unchecked schemas permit parameter tampering and prototype pollution attacks.

### Threat Vectors
- **Parameter Injection (OWASP LLM08 / CWE-20)**: Passing unexpected arguments that override internal tool settings or CLI flags.
- **Type Juggling & Memory Exploits (CWE-843)**: Supplying array or object types where string or integer types are expected.
- **Undeclared Capability Invocations (CWE-285)**: Calling internal or administrative tool functions not authorized for the session.

---

## 3. Architecture & Technical Blueprint

```text
Incoming JSON-RPC Tool Call (tools/call)
        │
        ▼ 1. ExtAuthz Pre-Execution Hook
ExtAuthz Schema Validator
        │
        ├── 2. Verify Protocol: Assert JSON-RPC 2.0 structure
        ├── 3. Capability Check: Assert tool name in authorized contract
        ├── 4. Load Tool InputSchema (e.g. read_text_file schema)
        ├── 5. Validate Properties:
        │      ├── Required parameters present (e.g. "path")
        │      ├── Parameter types strictly match schema (string)
        │      ├── additionalProperties: false enforced (no rogue keys allowed)
        │      └── String length and format constraints verified
        │
        ├── 6. PASS: Forward validated parameters to execution layer
        └── 7. FAIL: Return 403 Forbidden with detailed schema error envelope
```

---

## 4. Implementation Tasks

- [ ] Define canonical JSON schemas for all MCP tool definitions in `tool_contract.json`.
- [ ] Enforce `additionalProperties: false` across all tool schemas to prevent argument injection.
- [ ] Implement schema validation in the pre-execution authorization service.
- [ ] Implement length, format, and character set constraints on critical parameters (paths, identifiers).
- [ ] Add comprehensive unit tests validating rejection of missing fields, type mismatches, and extra properties.

---

## 5. Definition of Done (DoD) & Acceptance Criteria

1. **Strict Type Checking**: Any tool call with mismatched types (e.g. integer for a string field) is rejected with `403 Forbidden`.
2. **Rejection of Unknown Properties**: Any tool call containing undeclared arguments is immediately denied.
3. **Mandatory Parameter Validation**: Omitting required parameters produces a deterministic, descriptive error.
4. **Performance Standard**: Schema validation executes in $\le 1$ms per tool call.
5. **Automated Verification**: Complete unit test suite verifies schema rejection across all defined tools.

---

## 6. Verification & Validation Strategy

```bash
# Run schema rejection and validation tests
cd docker && go test -v -race -run TestExtAuthz_InvalidSchema ./security
```
