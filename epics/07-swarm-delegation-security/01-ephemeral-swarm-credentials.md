# TASK-SD-01: Ephemeral Role-Scoped Swarm Credentials & Least Privilege

## Epic: 07-swarm-delegation-security
**Status**: Ready for Implementation  
**Security Classification**: Critical (Multi-Agent Privilege Management)  
**Relevant Standards**: NIST SP 800-53 (AC-6 Least Privilege), OAuth 2.0 Token Exchange (RFC 8693)  

---

## 1. Context & Tooling Evaluation

In multi-agent architectures (e.g. Strands, AutoGen, CrewAI), complex tasks are broken down and delegated across autonomous agents (e.g. Planner, Researcher, Coder, Reviewer). If all agents share a single master API key or static root token, a compromise of any single sub-agent (via indirect prompt injection in untrusted data) grants the adversary full system permissions. We must evaluate credential delegation patterns enforcing least privilege.

### Tooling Trade-Off Matrix

| Credential Delegation Standard | Enterprise Fit | Pros | Cons / Constraints | Selection Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| **OAuth 2.0 Token Exchange (RFC 8693)** | High (Enterprise API Standard) | Standardized subject and actor tokens, downscoped scopes per role, short TTLs ($\le 5$m), supported by enterprise IdPs. | Requires token exchange endpoint; slight token issuance latency overhead. | **Selected Baseline Standard**: Ideal for REST/gRPC tool authorization across distributed agent roles. |
| **Short-Lived SPIFFE X.509 SVIDs** | High (Workload Layer) | Hardware/kernel attested, mutual TLS, strictly bounded lifetimes, tamper-proof. | Bound to container/workload identity rather than user session context; best for transport security. | **Transport Mesh Standard**: Pair with RFC 8693 user/session tokens. |
| **Macaroons / Biscuit Tokens** | High (Decentralized Attenuation) | Cryptographic caveats appended offline without calling central server; monotonic privilege reduction. | Less standardized enterprise library ecosystem; requires custom verification middleware. | **Next-Gen Research Pattern**: Evaluate for complex offline multi-hop swarms. |

---

## 2. Problem Statement & Threat Vectors

In multi-agent swarms, an unprivileged researcher agent tasks a privileged executor agent. If permissions are static, the researcher agent can trick the executor into reading internal secrets or writing destructive files (Confused Deputy attack). Additionally, long-lived credentials left in container environment variables can be exfiltrated and reused after task completion.

### Threat Vectors
- **Confused Deputy in Multi-Agent Swarms (CWE-441)**: Unprivileged agent tricking an executive agent into running dangerous actions.
- **Overprivileged Autonomous Workers (CWE-250)**: Read-only summarization workers possessing credentials capable of modifying data.
- **Credential Lingering (CWE-613)**: Sub-agent tokens remaining valid after the specific delegated task has concluded.

---

## 3. Architecture & Technical Blueprint

```text
Swarm Orchestrator (Multi-Agent Runner)
        │
        ├── 1. Dispatches Sub-task: "Analyze Document" -> Role: Researcher
        │
        ├── 2. Issues Ephemeral Role Token (RFC 8693 Token Exchange / Downscoped SVID)
        │      - Principal: "agent://swarm/researcher-42"
        │      - Delegator: "user://analyst-99"
        │      - Scopes: ["tools:read_text_file", "mcp:read"]
        │      - TTL: 300 seconds (5 minutes)
        │
        ▼ 3. Researcher Agent Invokes Tool via Security Gateway
Security Gateway (:8080)
        │
        ├── 4. ExtAuthz verifies role token:
        │      ├── Tool "read_text_file" in Scopes? -> ALLOW
        │      └── Tool "write_file" or "bash" in Scopes? -> DENY (403 Forbidden)
        │
        ▼ 5. Task Complete -> Token expires automatically
```

---

## 4. Implementation Tasks

- [ ] Implement role-scoped credential issuance in the multi-agent runner.
- [ ] Configure granular tool capability mappings per swarm role (Researcher = Read-Only; Coder = Sandbox-Only).
- [ ] Enforce short TTLs ($\le 5$ minutes) on all intermediate delegation tokens.
- [ ] Propagate delegation lineage headers (`X-Delegator`, `X-Agent-Role`) in tool requests.
- [ ] Add automated unit tests verifying that read-only roles cannot execute write or network tools.

---

## 5. Definition of Done (DoD) & Acceptance Criteria

1. **Role Isolation**: Agents operating in researcher or summarizer roles are blocked from write and execution tools.
2. **Ephemeral Lifetimes**: Sub-agent credentials expire within 5 minutes of issuance.
3. **Audit Provenance**: Tool execution audit logs accurately capture the specific sub-agent role and delegating principal.
4. **Automated Verification**: Complete test suite passes: `make strands-test && make strands-lab`.

---

## 6. Verification & Validation Strategy

```bash
# Run Strands role credentials and unit test suite
make strands-test

# Run Strands lab against isolated provider fixture
make strands-lab
```
