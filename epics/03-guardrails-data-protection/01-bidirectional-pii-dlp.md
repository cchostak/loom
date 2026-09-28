# TASK-GD-01: Bidirectional Data Loss Prevention (DLP) & PII Sanitization

## Epic: 03-guardrails-data-protection
**Status**: Ready for Implementation  
**Security Classification**: Critical (Data Loss Prevention & Privacy)  
**Relevant Standards**: GDPR (Art. 32), HIPAA Security Rule, PCI-DSS v4.0, NIST Privacy Framework  

---

## 1. Context & Tooling Evaluation

In enterprise commercial operations, sensitive customer data, corporate secrets, and regulated financial identifiers must be protected. Without bidirectional inspection, sensitive records can be sent to external LLM providers in prompts or leaked back to unprivileged users in model completions.

### Tooling Trade-Off Matrix

| DLP Technology | Enterprise Fit | Pros | Cons / Constraints | Selection Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| **Microsoft Presidio (Analyzer + Anonymizer)** | High (Open-Source Gold Standard) | Extensible recognizer framework, multi-language support, custom regex/entity models, local execution (no data leaves network). | Requires Python runtime or containerized microservice; NLP models add slight inference latency (~20ms). | **Selected Baseline Standard**: Deploy containerized Presidio service integrated into gateway boundary. |
| **Cloud Managed DLP (AWS Macie / Google Cloud DLP)** | High (Cloud Native) | High scale, enterprise entity catalogs, zero infrastructure management. | High per-megabyte inspection costs; egress latency to cloud API on synchronous critical path. | **Enterprise Cloud Option**: Use where cloud DLP is already enterprise standard. |
| **Regex & Pinned Token Scrubbers** | Medium (Fast Heuristic) | Ultra-fast execution (< 1ms), zero external dependencies, perfect for high-confidence structured formats (credit cards, SSNs, API keys). | Blind to contextual PII (e.g. names, addresses in natural text); high false positive/negative rate on unstructured data. | **First-Pass Filter**: Execute deterministic regex scrubber prior to NLP-based analyzers. |
| **LLM-Based DLP Scrubbers** | Medium (Context Aware) | Deep semantic understanding of contextual sensitivity. | High cost, adds 200-500ms latency to every request; non-deterministic masking. | **Not Recommended for Real-Time Path**: Restrict to offline batch data preparation. |

---

## 2. Problem Statement & Threat Vectors

Prompts containing customer SSNs, credit card numbers, or proprietary API keys violate data residency, privacy regulations, and compliance mandates if transmitted to third-party model providers. Additionally, hallucinating or compromised models can regurgitate private training data or internal connection strings in completions.

### Threat Vectors
- **Sensitive Data Disclosure (OWASP LLM06 / CWE-359)**: Leaking Personally Identifiable Information (PII) to public LLM endpoints.
- **Credential Exfiltration (CWE-522)**: Secret keys or database passwords embedded in prompts and exposed in provider logs.
- **Model Training Leakage (CWE-200)**: Regurgitation of proprietary company records in model completions.

---

## 3. Architecture & Technical Blueprint

```text
User / Agent Prompt
        │
        ▼ 1. Ingress Request
Guardrail DLP Pipeline (Edge Interceptor)
        │
        ├── 2. Pass 1: Deterministic Fast Scrubber (< 1ms)
        │      └── Regex scan for Credit Cards (Luhn), SSNs, Cloud API Keys (AWS, OpenAI)
        │
        ├── 3. Pass 2: Presidio Analyzer (< 25ms)
        │      └── Contextual entities: Person, Email, Location, Financial Accounts
        │
        ├── 4. Evaluate Tenant Policy:
        │      ├── IF Policy == "BLOCK" && High-Risk Detected -> Terminate with 403 Forbidden
        │      └── IF Policy == "REDACT" -> Anonymize inline: <REDACTED_SSN>
        │
        ▼ 5. Sanitized Prompt Forwarded to Model Provider
Model Provider API (OpenRouter / OpenAI / Anthropic)
        │
        ▼ 6. Model Output / Completion Body
Egress DLP Interceptor
        │
        ├── 7. Synchronous scan of completion text for secrets, credit cards, or internal PII
        │      └── Redact or quarantine if detected before client receipt
        │
        ▼ 8. Clean, compliant response returned to user
```

---

## 4. Implementation Tasks

- [ ] Implement two-pass DLP pipeline combining deterministic regex scrubbers with Presidio analyzer.
- [ ] Implement configurable tenant remediation policies: inline redaction vs. fail-closed 403 rejection.
- [ ] Implement bidirectional inspection hooks evaluating both ingress prompts and egress model outputs.
- [ ] Implement secret token scrubbers targeting cloud credentials, private keys, and API tokens.
- [ ] Add comprehensive test suites verifying masking and rejection across international PII formats.

---

## 5. Definition of Done (DoD) & Acceptance Criteria

1. **Synchronous Redaction**: Ingress prompts containing SSNs, credit cards, and API keys are scrubbed before reaching upstream providers.
2. **Fail-Closed Mode**: When configured to block, requests containing high-risk identifiers are rejected with `403 Forbidden`.
3. **Egress Protection**: Model outputs containing detected secrets or PII are masked before transmission to clients.
4. **Latency Budget**: Total DLP inspection overhead remains $\le 30$ms on average prompts.
5. **Automated Verification**: Complete test suite verifies masking accuracy across test payloads.

---

## 6. Verification & Validation Strategy

```bash
# Run PII detection, redaction, and boundary filtering test suites
cd docker && go test -v -race ./pii
cd docker && go test -v -race -run TestPII ./boundary
```
