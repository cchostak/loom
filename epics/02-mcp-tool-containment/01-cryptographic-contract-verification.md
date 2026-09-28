# TASK-MC-01: Cryptographic Tool Contract Signing & Verification

## Epic: 02-mcp-tool-containment
**Status**: Ready for Implementation  
**Security Classification**: Critical (Supply Chain & Tool Integrity)  
**Relevant Standards**: RFC 8032 (Ed25519), Sigstore / in-toto, Model Context Protocol Specification  

---

## 1. Context & Tooling Evaluation

Model Context Protocol (MCP) servers define the execution capabilities exposed to LLM agents. If an attacker tampers with the tool manifest on disk or in transit, they can register malicious capabilities or weaken schema constraints. We must evaluate cryptographic signing architectures to ensure tool contracts are verified against a trusted publisher root of trust.

### Tooling Trade-Off Matrix

| Signing Technology | Enterprise Fit | Pros | Cons / Constraints | Selection Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| **Ed25519 Standalone Signing** | High (High Speed / Microservice) | Ultra-fast verification (< 50μs), compact 64-byte signatures, small public key size (32 bytes), zero network dependencies. | Key distribution must be managed via configuration or KMS. | **Selected for Runtime Contract Verification**: Ideal for offline, containerized verification at boot. |
| **Sigstore / Cosign Keyless Signing** | High (Enterprise CI/CD Standard) | Ephemeral signing keys bound to OIDC identity via Fulcio/Rekor transparency log; no private keys to manage. | Requires external OIDC identity provider and Rekor transparency log access; slower in air-gapped environments. | **Recommended for CI/CD Pipeline Build Artifacts**: Sign release containers and tool contracts during automated builds. |
| **X.509 PKI Code Signing** | Medium (Traditional Enterprise) | Established enterprise CA hierarchies; supported by enterprise HSMs. | High certificate complexity, ASN.1 parsing overhead, CRL/OCSP revocation check latency. | **Legacy Option**: Supported when enterprise policy mandates corporate Root CA issuance. |

---

## 2. Problem Statement & Threat Vectors

Without cryptographic contract verification, an attacker who gains temporary file-write access inside a container or injects a malicious layer into an image can modify tool descriptions (inducing prompt injection) or register unauthorized tools (e.g. arbitrary bash execution) that the agent will discover and use.

### Threat Vectors
- **Tool Definition Poisoning (OWASP LLM08 / CWE-353)**: Ingesting unauthorized tool capabilities that execute shell commands or exfiltrate state.
- **Contract Tampering in CI/CD (CWE-494)**: Altering parameter descriptions to induce model behavior modification.
- **Replay & Impersonation (CWE-294)**: Forging MCP tool execution confirmations to bypass audit tracking.

---

## 3. Architecture & Technical Blueprint

```text
Build / Packaging Pipeline (Offline Publisher)
        │
        ▼ 1. Canonicalize and Hash tool_contract.json
Ed25519 Private Key (HSM / CI Secret Vault)
        │
        ▼ 2. Generate 64-byte Ed25519 Signature
Deployment Artifact (.loom/mcp_keys/publisher.pub + tool_contract.json.sig)
        │
        ▼ 3. Container Boot & ExtAuthz Initialization
ExtAuthz Security Service
        │
        ├── 4. Read tool_contract.json, signature, and publisher public key
        ├── 5. Execute ed25519.Verify(publicKey, contractBytes, signature)
        │      ├── VALID: Register tools and capabilities in memory
        │      └── INVALID: Abort service startup immediately (Fail-Closed)
        │
        ▼ 6. Runtime Tool Invocations
Signer Key (Runtime Session Key)
        │
        └── 7. Seal verified tool responses: X-Loom-MCP-Signature
```

---

## 4. Implementation Tasks

- [ ] Implement canonical JSON serialization for tool contract definitions.
- [ ] Build offline signing CLI/script using Ed25519 private key.
- [ ] Implement boot-time cryptographic verification in the tool authorization service.
- [ ] Enforce fail-closed termination if contract signature is missing, invalid, or forged.
- [ ] Implement runtime response sealing using ephemeral session keys.
- [ ] Create automated unit tests validating valid signatures, altered payloads, and wrong keys.

---

## 5. Definition of Done (DoD) & Acceptance Criteria

1. **Cryptographic Integrity**: Any alteration to `tool_contract.json` (even 1 byte) causes signature verification to fail.
2. **Fail-Closed Startup**: The security authorization service aborts startup immediately if contract verification fails.
3. **Offline Capability**: Verification runs entirely locally without network calls to external key servers.
4. **Performance Standard**: Contract verification completes in $\le 5$ms during boot.
5. **Automated Test Coverage**: Complete test suite covers signature validation, tampering, and key rotation scenarios.

---

## 6. Verification & Validation Strategy

```bash
# Verify tool contract signing and validation test suite
make mcp-test
cd docker && go test -v -race -run TestExtAuthz_ContractVerification ./security
```
