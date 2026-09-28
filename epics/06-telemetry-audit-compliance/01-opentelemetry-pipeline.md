# TASK-TA-01: Privacy-Preserving OpenTelemetry Pipeline (OTTL Transforms)

## Epic: 06-telemetry-audit-compliance
**Status**: Ready for Implementation  
**Security Classification**: High (Observability & Privacy Scrubbing)  
**Relevant Standards**: OpenTelemetry Semantic Conventions for GenAI, GDPR Art. 25 (Privacy by Design), SOC 2 CC6.1  

---

## 1. Context & Tooling Evaluation

Standard distributed tracing captures full HTTP request/response payloads, headers, and query strings. In AI applications, this means user prompts containing personal data or proprietary business secrets end up stored indefinitely in observability backends, bypassing access controls and violating compliance regulations.

### Tooling Trade-Off Matrix

| Telemetry Collector | Enterprise Fit | Pros | Cons / Constraints | Selection Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| **OpenTelemetry Collector Contrib** | High (Industry Standard) | Vendor-neutral, rich processor ecosystem (OTTL - OpenTelemetry Transformation Language), native GenAI semantic conventions, multiplexing exporters. | Requires configuring and running collector container; memory tuning for high-throughput traces. | **Selected Baseline Standard**: Deploy standard OTel Collector with OTTL privacy processors. |
| **Fluent Bit / Vector** | High (High Throughput Logging) | Ultra-low memory footprint, fast Rust/C implementations, excellent for raw log forwarding. | Less mature native support for OpenTelemetry GenAI trace semantic conventions and trace-to-finding transformation. | **Supplemental**: Use for host and container runtime log collection. |
| **Proprietary Vendor Agents (Datadog / Dynatrace)** | High (Managed APM) | Turnkey dashboards, out-of-the-box alerting, automated anomaly detection. | Vendor lock-in; proprietary ingestion protocols; risk of unredacted prompt telemetry transmitted to vendor cloud. | **Egress Target Only**: Route scrubbed telemetry from OTel Collector to enterprise APM. |

---

## 2. Problem Statement & Threat Vectors

If distributed tracing captures raw prompt bodies, any developer, support engineer, or attacker with access to the tracing dashboard (e.g. Jaeger, Zipkin, Datadog) can view unredacted customer data, proprietary code, or confidential employee communications.

### Threat Vectors
- **PII Exposure in Observability Backends (OWASP LLM06 / CWE-532)**: User prompts and model outputs leaked into telemetry indexes.
- **Trace Attribute Poisoning**: Malicious payloads injecting invalid attributes to crash telemetry collectors.
- **Compliance Audit Gaps (CWE-778)**: Failure to capture GenAI cost and model attribution across distributed agent spans.

---

## 3. Architecture & Technical Blueprint

```text
API Gateway & AI Workloads
        │
        ▼ (OTLP gRPC Spans & Metrics)
OpenTelemetry Collector Contrib (:4317 / :4318)
        │
        ├── 1. Receiver: otlp (gRPC / HTTP)
        │
        ├── 2. Processor: transform/privacy (OpenTelemetry Transformation Language - OTTL)
        │      ├── Strips raw user prompt text and completion bodies
        │      └── Preserves approved GenAI telemetry attributes:
        │          - gen_ai.system, gen_ai.request.model, gen_ai.response.model
        │          - gen_ai.usage.input_tokens, gen_ai.usage.output_tokens, gen_ai.usage.cost
        │          - llm.cost, llm.provider, http.status_code, loom.workload, spiffe.identity
        │
        ├── 3. Exporter: otlp_grpc -> Jaeger (:4317) [Tracing Visualization]
        └── 4. Exporter: otlp_http/normalizer -> Normalizer Service (:8080/v1/traces) [Compliance]
```

---

## 4. Implementation Tasks

- [ ] Deploy OpenTelemetry Collector with OTLP receivers enabled.
- [ ] Configure `transform/privacy` processor using OTTL statements to strip raw text while retaining GenAI attributes.
- [ ] Implement dual-export routing: traces to distributed tracing backend, and compliance spans to normalizer.
- [ ] Configure collector resource limits (memory ballast, batching) to prevent out-of-memory crashes.
- [ ] Add automated test suites verifying attribute stripping and span forwarding.

---

## 5. Definition of Done (DoD) & Acceptance Criteria

1. **Prompt Stripping**: Tracing backends receive spans with zero raw prompt or completion text.
2. **GenAI Attribute Retention**: Spans accurately preserve model name, token counts, and dollar cost attributes.
3. **Dual Pipeline Export**: Traces are delivered concurrently to visualization backends and compliance finding queues.
4. **Automated Verification**: Complete configuration passes validation: `make check`.

---

## 6. Verification & Validation Strategy

```bash
# Validate OpenTelemetry collector and Docker Compose configuration
make check
```
