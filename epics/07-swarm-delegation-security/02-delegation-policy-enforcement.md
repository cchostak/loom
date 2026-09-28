# TASK-SD-02: Inter-Agent Delegation Policy Enforcement (CEL & OPA Rules)

## Epic: 07-swarm-delegation-security
**Status**: Ready for Implementation  
**Security Classification**: High (Delegation Control & Privilege Escalation Prevention)  
**Relevant Standards**: NIST SP 800-207 (Zero Trust Architecture), Common Expression Language (CEL)  

---

## 1. Context & Tooling Evaluation

In multi-agent swarms, agent handoffs must follow strict security state transitions. An unprivileged agent must not be permitted to directly task a privileged execution agent without traversing an intermediate reviewer or planner stage. We must evaluate policy engines capable of enforcing declarative transition rules at gateway speed.

### Tooling Trade-Off Matrix

| Policy Engine Technology | Enterprise Fit | Pros | Cons / Constraints | Selection Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| **Common Expression Language (CEL)** | High (Gateway Native & Fast) | Microsecond evaluation (< 10μs), deterministic, non-Turing complete (cannot loop infinitely), native in Envoy, AgentGateway, K8s. | Less suited for deeply nested relational graph traversals across historical states. | **Selected Baseline Standard**: Ideal for edge gateway delegation rules and tool allowlists. |
| **Open Policy Agent (OPA / Rego)** | High (Enterprise General Policy) | Rich declarative language (Rego), deep structural data querying, mature enterprise ecosystem. | Adds 2-5ms evaluation latency; higher memory footprint; running OPA sidecar adds complexity. | **Enterprise Policy Server Standard**: Use when centralizing cross-cloud enterprise policy management. |
| **AWS Cedar** | High (Formal Verification) | Built specifically for fine-grained authorization; supports formal verification with automated SMT solvers. | Tightly coupled to AWS ecosystem / Cedar SDK; requires custom gateway integration. | **Enterprise AWS Standard**: Recommended for AWS-centric enterprise agent pools. |

---

## 2. Problem Statement & Threat Vectors

Without declarative delegation enforcement, an untrusted agent (e.g. web search scraper) can directly invoke a database modification or code execution agent, bypassing the planner's safety guardrails (Privilege Escalation via Multi-Agent Delegation).

### Threat Vectors
- **Privilege Escalation via Agent Delegation (CWE-269)**: Low-trust agent tasking high-trust agent with file modification or network calls.
- **Deep Delegation Hiding**: Chaining multiple agents to obscure the original untrusted caller.
- **Unauthorized Cross-Domain Tasking**: Agents crossing organizational tenant boundaries via swarm handoffs.

---

## 3. Architecture & Technical Blueprint

```text
Caller Agent (Role: Researcher, Identity: spiffe://loom.local/workload/researcher)
        │
        ▼ 1. Delegation Request to Target Agent (Role: Executor)
Security Gateway Delegation Interceptor
        │
        ├── 2. Evaluate CEL Delegation Policy:
        │      expression: """
        │        caller.role == 'orchestrator' ||
        │        (caller.role == 'researcher' && target.role == 'reviewer') ||
        │        (caller.role == 'reviewer' && target.role == 'executor')
        │      """
        │
        ├── 3. Enforce Maximum Delegation Depth:
        │      Assert caller.delegation_depth < 4
        │
        ├── 4. Evaluate: Is Transition Allowed?
        │      ├── NO (Researcher -> Executor directly):
        │      │      └── Terminate with 403 Forbidden ("Illegal inter-agent delegation transition")
        │      └── YES:
        │             ├── Increment delegation_depth
        │             └── Forward request to Target Agent
        │
        ▼ 5. Pass: Dispatched to Reviewer Agent
```

---

## 4. Implementation Tasks

- [ ] Define declarative delegation transition schemas mapping allowed role-to-role handoffs.
- [ ] Configure Common Expression Language (CEL) rules for agent handoff authorization.
- [ ] Implement delegation depth counter and enforce hard maximum hop limits.
- [ ] Propagate signed delegation headers across swarm message boundaries.
- [ ] Add automated unit tests verifying rejection of unauthorized direct handoffs.

---

## 5. Definition of Done (DoD) & Acceptance Criteria

1. **State Transition Enforcement**: Unapproved role transitions (e.g. researcher directly tasking executor) are rejected with `403 Forbidden`.
2. **Depth Limiting**: Swarm handoffs exceeding maximum delegation depth are halted with an explicit policy denial.
3. **Audit Trail**: Every inter-agent handoff event records caller role, target role, and decision in telemetry.
4. **Automated Verification**: Complete test suite passes: `make strands-test`.

---

## 6. Verification & Validation Strategy

```bash
# Verify Strands swarm delegation and role boundaries
make strands-test
```
