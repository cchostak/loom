# TASK-CR-01: Model Catalog Governance & Real-Time Token Valuation

## Epic: 05-cost-and-resilience
**Status**: Ready for Implementation  
**Security Classification**: Medium (FinOps & Cost Governance)  
**Relevant Standards**: FinOps Foundation Framework, NIST AI RMF (Measure 2.7)  

---

## 1. Context & Tooling Evaluation

In enterprise multi-tenant environments, AI cost management requires granular attribution. Models vary dramatically in pricing (e.g. GPT-4o vs GPT-4o-mini vs Claude 3.5 Sonnet), with separate rates for input tokens, output tokens, and cached tokens. Real-time cost governance requires a centralized model catalog.

### Tooling Trade-Off Matrix

| Model Catalog Solution | Enterprise Fit | Pros | Cons / Constraints | Selection Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| **Gateway Native Model Catalog** | High (Edge Performance) | Evaluated directly at the gateway ingress; pre-admission cost estimation; zero external network hops; declarative YAML/JSON configuration. | Requires syncing catalog when provider prices update. | **Selected Baseline Standard**: Manage model rates declaratively at the gateway layer. |
| **Centralized FinOps API Service** | High (Enterprise Multi-Cloud) | Real-time billing synchronization across AWS Bedrock, Azure OpenAI, GCP Vertex AI, and direct APIs. | Adds a network lookup on the critical path if not aggressively cached; higher infrastructure overhead. | **Enterprise FinOps Standard**: Recommended when enterprise already operates an enterprise cloud FinOps platform. |
| **Static Hardcoded Constants** | Low (Brittle) | Zero setup effort in code. | Model pricing changes require code deployments; prone to billing drift and misattribution. | **Anti-Pattern**: Do not embed static price floats directly in application code. |

---

## 2. Problem Statement & Threat Vectors

Without real-time token valuation, enterprise organizations suffer from uncontrolled cloud expenditure ("bill shock"), lack of visibility into multi-agent swarm consumption, and inability to enforce department chargebacks. Rogue or compromised workloads can exploit cheap tier endpoints to exfiltrate massive token volumes or spam expensive frontier models.

### Threat Vectors
- **Model Cost Tampering / Misattribution**: Inaccurate billing attribution across business units.
- **Provider Arbitrage Exploitation**: Routing expensive queries to high-cost models without administrative authorization.
- **Runaway Token Generation (OWASP LLM04)**: Uncontrolled generation loops running up catastrophic cloud model bills.

---

## 3. Architecture & Technical Blueprint

```text
Incoming Model Inference Request (Model: "openai/gpt-4o-mini", Est. Input Tokens: 2,500)
        │
        ▼ 1. API Security Gateway Edge
Model Catalog Engine
        │
        ├── 2. Match Provider & Model Configuration:
        │      - Provider: "openrouter"
        │      - Model: "openai/gpt-4o-mini"
        │      - Rates: Input: "$0.15" / 1M, Output: "$0.60" / 1M
        │      - Context Window: 128,000 tokens
        │      - Max Output: 16,384 tokens
        │
        ├── 3. Pre-Admission Check:
        │      Estimate Cost = (2500 / 1,000,000) * $0.15 = $0.000375
        │      Assert caller remaining budget >= Estimate Cost
        │
        ▼ 4. Upstream Model Execution
Model Response Body (Actual: 2,480 input tokens, 310 output tokens)
        │
        ├── 5. Exact Cost Settlement:
        │      Actual Cost = (2480 * 0.00000015) + (310 * 0.00000060) = $0.000558
        │      Deduct exact cost from tenant ledger in database
        │
        ▼ 6. OpenTelemetry Span Emission
Span annotated with standard GenAI semantic attributes:
- gen_ai.request.model: "openai/gpt-4o-mini"
- gen_ai.usage.input_tokens: 2480
- gen_ai.usage.output_tokens: 310
- gen_ai.usage.cost: 0.000558
```

---

## 4. Implementation Tasks

- [ ] Define declarative model catalog schema supporting providers, models, context windows, and per-token rates.
- [ ] Configure pricing rates for supported enterprise models (input, output, and cache rates).
- [ ] Implement pre-admission cost estimation prior to upstream dispatch.
- [ ] Implement post-response exact cost settlement against tenant budgets.
- [ ] Emit standardized `gen_ai.usage.cost` attributes on all OpenTelemetry spans.
- [ ] Add automated unit tests verifying catalog deserialization and cost calculation precision.

---

## 5. Definition of Done (DoD) & Acceptance Criteria

1. **Declarative Catalog**: Model catalog configuration passes validation with edge gateway binary.
2. **Accurate Calculation**: Exact token costs are calculated according to published per-million token rates.
3. **Telemetry Attribution**: Every completed inference span includes standard GenAI token and cost attributes.
4. **Automated Verification**: Complete test suite passes: `make check`.

---

## 6. Verification & Validation Strategy

```bash
# Validate gateway configuration and model catalog schemas
make check

# Run Go policy tests for model catalog rates
cd docker && go test -v -run TestCELPolicy ./...
```
