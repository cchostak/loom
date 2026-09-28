# TASK-CR-03: Upstream LLM Circuit Breakers & Outage Mitigation

## Epic: 05-cost-and-resilience
**Status**: Ready for Implementation  
**Security Classification**: High (System Availability & Cascading Outage Prevention)  
**Relevant Standards**: NIST SP 800-160 (Systems Security Engineering: Resilience), RFC 6587  

---

## 1. Context & Tooling Evaluation

Cloud AI providers experience periodic throttling, degraded latencies, and regional outages. If concurrent multi-agent requests continue hitting a failing upstream provider, gateway worker pools, memory, and TCP connections become exhausted, cascading into total infrastructure failure. Automated circuit breaking and multi-provider failover are essential.

### Tooling Trade-Off Matrix

| Resilience Architecture | Enterprise Fit | Pros | Cons / Constraints | Selection Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| **Gateway Native Circuit Breaking (Envoy / AgentGateway)** | High (Perimeter Defense) | Protects gateway worker threads; connection pool limits; consecutive error thresholds; zero application code changes required. | Coarse-grained per upstream cluster; requires gateway configuration updates. | **Selected Baseline Standard**: Deploy native circuit breaking on all upstream LLM clusters. |
| **Application-Level Resilience (e.g. Resilience4j)** | High (Application Level) | Fine-grained fallback responses (e.g. returning cached summaries or degrading to smaller models). | Requires embedding libraries in every microservice; inconsistent behavior across polyglot swarms. | **Supplemental**: Implement fallback heuristics in agent orchestrators. |
| **Multi-Provider Dynamic Failover** | High (Zero Downtime) | Automatically routes traffic from failing provider (e.g. OpenAI) to alternate equivalent provider (e.g. Anthropic, Vertex AI). | Token formatting and tool calling schema differences between providers must be normalized. | **Recommended for Mission-Critical SLAs**: Implement dynamic provider failover in gateway routing. |

---

## 2. Problem Statement & Threat Vectors

Upstream model providers frequently throttle callers (HTTP 429) or return transient 502/503 errors during peak usage. When autonomous agents aggressively retry failed requests in tight loops, they exacerbate provider throttling, hang thread pools, and starve adjacent enterprise workloads.

### Threat Vectors
- **Cascading Failure & Thread Starvation (CWE-400)**: Hanging upstream model requests exhausting gateway connection pools.
- **Throttling Snowball Effect**: Aggressive retries without exponential backoff worsening rate limits.
- **Uncontrolled Latency Spikes**: Degrading end-user application response times during cloud provider incidents.

---

## 3. Architecture & Technical Blueprint

```text
Incoming Model Inference Request
        │
        ▼ 1. AgentGateway Dispatch
Circuit Breaker State Machine
        │
        ├── State: CLOSED (Normal Operation)
        │      ├── Track consecutive 5xx, 429, and timeout responses
        │      └── IF consecutive_failures >= 3:
        │             └── Transition State -> OPEN
        │
        ├── State: OPEN (Tripped)
        │      ├── Intercept all calls immediately without calling upstream
        │      ├── Return 503 Service Unavailable ("Upstream circuit open")
        │      ├── Emit OTel ControlEvent: event="circuit_tripped"
        │      └── Maintain cooldown timer (e.g. 30 seconds)
        │
        └── State: HALF-OPEN (Probing Recovery)
               ├── Allow single probe request through to upstream
               ├── IF probe succeeds -> Transition State -> CLOSED
               └── IF probe fails -> Reset cooldown timer -> OPEN
```

---

## 4. Implementation Tasks

- [ ] Configure connection pool limits, pending request limits, and max requests per connection in the gateway.
- [ ] Configure outlier detection and consecutive 5xx failure ejection thresholds.
- [ ] Implement exponential backoff with jitter on transient upstream 429/503 errors.
- [ ] Implement fail-fast `503 Service Unavailable` responses when upstream circuits are open.
- [ ] Route circuit trip events into the telemetry pipeline for posture drift tracking.
- [ ] Add automated integration tests verifying circuit opening, cooldown, and recovery.

---

## 5. Definition of Done (DoD) & Acceptance Criteria

1. **Fast Failure**: Requests arriving while an upstream provider is tripped receive immediate `503 Service Unavailable` without consuming connection resources.
2. **Deterministic Tripping**: Three consecutive upstream 5xx or timeout responses reliably trip the circuit.
3. **Telemetry Emission**: Tripped circuits emit structured telemetry events normalizing into posture drift findings.
4. **Automated Verification**: Complete test suite passes: `make test-telemetry`.

---

## 6. Verification & Validation Strategy

```bash
# Verify circuit trip telemetry normalization
make test-telemetry
```
