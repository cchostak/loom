# TASK-GD-03: Multi-Stage Semantic Guardrails & Automated Adversarial Red Teaming

## Epic: 03-guardrails-data-protection
**Status**: Ready for Implementation  
**Security Classification**: High (Adversarial Robustness & Model Evaluation)  
**Relevant Standards**: NIST AI Risk Management Framework (AI RMF 1.0), OWASP LLM Top 10, MITRE ATLAS  

---

## 1. Context & Tooling Evaluation

Static string heuristics and regex patterns fail against linguistic obfuscation, role-play framing ("Do Anything Now"), multi-lingual translations, and cipher encodings. Enterprises require multi-stage guardrail architectures validated by automated adversarial evaluation suites in continuous integration.

### Tooling Trade-Off Matrix

| Guardrail / Red-Teaming Solution | Enterprise Fit | Pros | Cons / Constraints | Selection Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| **Meta Llama Guard (3 / 3-8B)** | High (Open Industry Standard) | 14 hazard categories (violence, hate, exfiltration, software attacks), open-weights, high accuracy, runs on private infrastructure. | Requires GPU/accelerator hosting; adds ~30-60ms inference latency. | **Selected Semantic Classifier**: Deploy for synchronous high-risk prompt/output safety classification. |
| **NVIDIA NeMo Guardrails** | High (Programmable Guardrails) | Programmable Colang policies, topical rail enforcement, dialog flow containment. | Slower execution on complex multi-turn dialogs; learning curve for Colang DSL. | **Recommended for Conversational Rails**: Best suited for customer-facing chatbot boundaries. |
| **Commercial Guardrail APIs (Lakera / Protect AI)** | High (Managed Enterprise SaaS) | Comprehensive threat databases, zero infrastructure hosting, fast time-to-value. | SaaS dependency; prompt data leaves boundary unless enterprise on-premise appliance used; per-query cost. | **Commercial Alternative**: Evaluate for enterprises standardizing on managed security vendors. |
| **Continuous Red-Teaming (Garak / PyRIT)** | High (CI/CD Red Teaming) | Automated adversarial attack simulation (jailbreaks, encoding bypasses, model theft), reproducible metrics, release gating. | Offline batch evaluation; runs during CI/CD rather than in the real-time request path. | **Mandatory CI Gate**: Integrate into pipeline to measure bypass regression across code releases. |

---

## 2. Problem Statement & Threat Vectors

Adversaries continuously innovate prompt injection techniques to bypass simple filters. Without automated adversarial testing, code or model changes can introduce regressions that expose corporate data or grant unauthenticated tool access without the development team's knowledge.

### Threat Vectors
- **Jailbreak Bypasses (OWASP LLM01)**: Obfuscated framing (hypotheticals, fictional world roleplay) circumventing basic keyword blocks.
- **Multilingual Evasion**: Attacking safety filters by translating prohibited prompts into low-resource languages.
- **Safety Regression in CI/CD**: Changes to system prompts or gateway configuration weakening previously validated protections.

---

## 3. Architecture & Technical Blueprint

```text
Incoming Prompt / Completion Body
        │
        ▼
Tier 1: Fast Deterministic Filter (< 2ms)
        ├── Presidio PII & secret regex scanning
        ├── Special token / delimiter stripping
        └── Known adversarial signature lookup
        │ (Passed)
        ▼
Tier 2: Semantic Guardrail Classifier (Llama Guard / NeMo: ~30-50ms)
        ├── Taxonomical Classification (Violence, Exfiltration, Code Sabotage)
        ├── Evaluate Confidence Scores against Tenant Thresholds
        │      ├── IF Violation Detected: Terminate with 403 Forbidden + Audit Finding
        │      └── IF Clear: Proceed to Model Inference
        │
        ▼ (Continuous Validation in CI/CD Pipeline)
Automated Red Teaming Harness (Swarm Lab / Garak / PyRIT)
        ├── Executes automated multi-turn adversarial attack suites
        ├── Injects obfuscated jailbreaks and encoding payloads
        ├── Measures bypass rate and latency impact
        └── Generates machine-readable lab-score.json for release gating
```

---

## 4. Implementation Tasks

- [ ] Implement Tier 1 deterministic fast filter in gateway boundary handlers.
- [ ] Deploy Tier 2 semantic classifier container using open-weights safety model (Llama Guard).
- [ ] Configure tenant safety thresholds and classification categories.
- [ ] Build automated adversarial evaluation harness (Swarm Lab) executing benchmark attack vectors.
- [ ] Export machine-readable evaluation reports (`make lab-json`) for automated CI release gating.
- [ ] Enforce zero high-severity bypass regression policy in build pipelines.

---

## 5. Definition of Done (DoD) & Acceptance Criteria

1. **Multi-Tier Execution**: Requests pass through deterministic filter followed by semantic safety classification.
2. **Hazard Classification**: Prompts falling into prohibited hazard categories are blocked with `403 Forbidden`.
3. **Automated Red Teaming**: Adversarial evaluation suite executes automatically in CI and emits machine-readable score reports.
4. **Zero Regression Gate**: CI pipeline fails if high-severity jailbreak bypasses exceed 0%.
5. **Latency Budget**: Total guardrail evaluation overhead remains $\le 60$ms.

---

## 6. Verification & Validation Strategy

```bash
# Execute adversarial swarm lab evaluation
make lab

# Emit machine-readable lab score report
make lab-json
```
