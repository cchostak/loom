# TASK-CR-02: Multi-Tenant Dollar Budgets & Distributed Quotas

## Epic: 05-cost-and-resilience
**Status**: Ready for Implementation  
**Security Classification**: Critical (Denial-of-Wallet Prevention)  
**Relevant Standards**: OWASP Top 10 for LLM (LLM04 - Model Denial of Service), ISO 27001 (A.12.1.3 Capacity Management)  

---

## 1. Context & Tooling Evaluation

In multi-agent architectures, agents can trigger thousands of recursive inference operations in minutes. Without durable, distributed quota accounting, single-instance in-memory counters reset whenever a container restarts or crashes, allowing rogue or compromised workloads to bypass financial safety limits.

### Tooling Trade-Off Matrix

| Quota Storage Architecture | Enterprise Fit | Pros | Cons / Constraints | Selection Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| **Distributed Cache (Redis / Valkey)** | High (Multi-Instance Clustered) | Sub-millisecond latency, atomic Lua scripts for token bucket and sliding window evaluation, shared across hundreds of gateway replicas. | Requires managed Redis cluster infrastructure (ElastiCache/MemoryDB). | **Selected Enterprise Clustered Standard**: Recommended for multi-replica horizontal deployments. |
| **Persistent Embedded DB (SQLite / PostgreSQL)** | High (Single Node & Lab) | Persistent state surviving container restarts; zero external network dependencies; supported natively by AgentGateway. | SQLite concurrency bottlenecks under high concurrent write loads across multiple hosts. | **Selected Baseline Standard**: Ideal for standalone gateways and developer environments. |
| **In-Memory Go Counters** | Low (Ephemeral) | Zero infrastructure dependencies; fast in-process atomic operations. | State wiped on every container restart; non-shared across replicas; vulnerable to crash-to-reset attacks. | **Anti-Pattern**: Do not use in production enterprise deployments. |

---

## 2. Problem Statement & Threat Vectors

Autonomous multi-agent swarms can enter infinite execution loops or generate runaway sub-queries, quickly consuming thousands of dollars in cloud LLM API credits (Denial-of-Wallet). Furthermore, an attacker capable of crashing a gateway container can reset in-memory counters to bypass limits.

### Threat Vectors
- **Denial of Wallet (OWASP LLM04)**: Runaway agent query loops exhausting enterprise LLM credits.
- **Budget Counter Reset via Crash (CWE-362)**: Inducing crashes in gateway containers to reset in-memory budget limits.
- **Cross-Tenant Budget Starvation**: One tenant monopolizing global rate limits and blocking other business units.

---

## 3. Architecture & Technical Blueprint

```text
Incoming Request (Principal: "analyst-1", Tenant: "finance-dept")
        │
        ▼ 1. Ingress Admission
Distributed Budget Engine (Gateway / Redis / SQLite)
        │
        ├── 2. Query Durable State for Tenant "finance-dept":
        │      ├── Retrieve spent_usd for current sliding window (day)
        │      └── Retrieve used_tokens for current window (hour)
        │
        ├── 3. Evaluate Dual Quota Limits:
        │      - Daily Dollar Budget: $50.00 / day
        │      - Hourly Token Budget: 500,000 tokens / hour
        │      - Burst RPM Limit: 60 requests / minute
        │
        ├── 4. Evaluate Thresholds:
        │      ├── IF (spent_usd + estimated_cost > $50.00) OR (tokens > 500k):
        │      │      ├── Action: "block" (Fail-Closed)
        │      │      ├── Emit OTel Finding: reason="budget_exhausted"
        │      │      └── Return 429 Too Many Requests ("Daily budget exhausted")
        │      └── IF within limits:
        │             ├── Atomically reserve estimated quota
        │             └── Proceed to Model Inference Dispatch
        │
        ▼ 5. Post-Execution Settlement
Reconcile actual token usage and adjust reserved budget atomically
```

---

## 4. Implementation Tasks

- [ ] Configure persistent database backing for gateway budget and rate limit state.
- [ ] Implement dual-dimension quota enforcement: currency spending caps ($/day) and token limits (tokens/hr).
- [ ] Implement atomic quota reservation and post-execution settlement.
- [ ] Enforce deterministic fail-closed blocking returning `429 Too Many Requests` on exhaustion.
- [ ] Emit structured control events and audit findings upon quota breaches.
- [ ] Add automated test suites verifying budget persistence across container restarts.

---

## 5. Definition of Done (DoD) & Acceptance Criteria

1. **Durable Persistence**: Budget counters persist across container restarts without data loss.
2. **Deterministic Blocking**: Requests exceeding dollar or token budgets are blocked at the perimeter edge.
3. **Multi-Tenant Isolation**: Each tenant's quota operates in complete isolation; one tenant cannot exhaust another's budget.
4. **Automated Verification**: Complete test suite passes: `cd docker && go test -v -run TestCELPolicy ./...`.

---

## 6. Verification & Validation Strategy

```bash
# Validate gateway budget schema and compose config
make check

# Run Go CEL budget policy test suite
cd docker && go test -v -race -run TestCELPolicy ./...
```
