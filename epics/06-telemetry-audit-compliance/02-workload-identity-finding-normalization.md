# TASK-TA-02: Workload Identity Enrichment & Unified Governance Finding Normalization

## Epic: 06-telemetry-audit-compliance
**Status**: Ready for Implementation  
**Security Classification**: High (Audit Normalization & Workload Attestation)  
**Relevant Standards**: OpenTelemetry Semantic Conventions, SPIFFE, SOC 2 CC7.2, EU AI Act Art. 12  

---

## 1. Context & Tooling Evaluation

Enterprise compliance auditing (SOC 2, ISO 27001, EU AI Act) requires proving non-repudiation: which exact workload initiated an inference request, what model was invoked, what tokens were consumed, and what policy decisions occurred. Raw OTel trace spans are noisy and disconnected from compliance frameworks; they must be normalized into structured governance findings.

### Tooling Trade-Off Matrix

| Schema & Ingestion Standard | Enterprise Fit | Pros | Cons / Constraints | Selection Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| **Unified Governance Finding Schema** | High (Audit Centric) | Structured categorization (`policy_violation`, `posture_drift`, `audit_finding`), compliance framework tags, normalized severity, includes SPIFFE ID. | Requires running a lightweight normalization microservice. | **Selected Baseline Standard**: Deploy `normalizer` service converting OTel spans to unified findings. |
| **Direct OTel Span Dumps** | Low (Audit Hostile) | Zero transformation overhead; streams raw traces directly to storage. | Disconnected from compliance rules; auditors cannot easily query policy violations or cost spikes. | **Anti-Pattern**: Do not rely on raw trace logs for formal compliance audits. |
| **Enterprise SIEM Formats (OCSF / CEF / ASIM)** | High (Enterprise SIEM) | Native ingestion into Splunk, Microsoft Sentinel, and AWS Security Lake. | Format variations between enterprise SIEM vendors; complex mapping logic. | **Egress Standard**: Map unified finding records to OCSF/CEF when exporting to enterprise SIEMs. |

---

## 2. Problem Statement & Threat Vectors

In multi-agent swarms, when a policy breach, data exfiltration, or runaway cost event occurs, traditional logs fail to identify which autonomous agent sub-task initiated the call. Without cryptographic workload identity binding, teams cannot determine accountability or isolate malfunctioning agent roles.

### Threat Vectors
- **Repudiation of AI Actions (CWE-312)**: Inability to prove which agent or service initiated a high-cost or policy-violating inference.
- **Audit Tampering & Schema Inconsistency**: Disconnected log formats preventing automated compliance verification.
- **Unattributed Cost Spikes**: Inability to identify runaway workloads in multi-agent swarms.

---

## 3. Architecture & Technical Blueprint

```text
OTel Collector Contrib
        │
        ▼ (HTTP POST /v1/traces)
Normalizer Service (docker/enterprise/normalizer.go)
        │
        ├── 1. Ingest OTLP Traces Payload
        ├── 2. Extract Span Attributes:
        │      - Model: gen_ai.request.model / gen_ai.response.model
        │      - Usage: input_tokens, output_tokens, dollar_cost
        │      - Workload: loom.workload / service.name
        │
        ├── 3. Inject Cryptographic Workload Identity:
        │      spiffe://loom.local/workload/<service_name>
        │
        ├── 4. Transform into Unified Finding Schema:
        │      - finding_type: "audit_finding"
        │      - rule_id: "loom.agentgateway.cost_attestation"
        │      - severity: "info"
        │      - affected_resource: { id: span_id, spiffe_id: "spiffe://..." }
        │      - compliance_frameworks: ["SOC2_CC6_1", "ISO27001_A12", "EU_AI_ACT_ART12"]
        │
        ▼ 5. Persist to Tamper-Evident Storage (normalization_queue)
SQLite / PostgreSQL Store
        │
        ▼ 6. Authenticated GET /findings
Auditor / Enterprise SIEM Scraper
```

---

## 4. Implementation Tasks

- [ ] Extend governance finding schema with optional `spiffe_id` attribute in `AffectedResource`.
- [ ] Implement `POST /v1/traces` endpoint in the normalizer service accepting OTLP trace JSON.
- [ ] Implement attribute extraction for standard GenAI model, token, and cost metrics.
- [ ] Implement automated injection of SPIFFE workload identity based on calling container attestation.
- [ ] Implement mapping logic converting control events and spans into canonical `UnifiedFinding` records.
- [ ] Add automated unit tests verifying trace ingestion, SPIFFE identity injection, and finding serialization.

---

## 5. Definition of Done (DoD) & Acceptance Criteria

1. **Endpoint Ingestion**: `POST /v1/traces` accepts OTLP trace payloads and converts them to findings.
2. **Workload Attribution**: Output findings include valid SPIFFE IDs (`spiffe://loom.local/workload/...`).
3. **Compliance Classification**: Findings include tags for SOC 2, ISO 27001, and EU AI Act compliance controls.
4. **Automated Verification**: Complete test suite passes: `make test-telemetry`.

---

## 6. Verification & Validation Strategy

```bash
# Verify telemetry span normalization and SPIFFE workload identity injection
make test-telemetry
```
