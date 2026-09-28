# TASK-GD-02: Prompt Injection Quarantine & Delimiter Sanitization

## Epic: 03-guardrails-data-protection
**Status**: Ready for Implementation  
**Security Classification**: Critical (Model Control Plane Security)  
**Relevant Standards**: OWASP Top 10 for LLM (LLM01 - Prompt Injection), MITRE ATLAS (AML.T0051)  

---

## 1. Context & Tooling Evaluation

Prompt injection is the root vulnerability of autonomous LLM applications. An adversary crafts inputs designed to hijack the model's instruction hierarchy, causing it to disregard system rules, exfiltrate data, or invoke unauthorized tools. We must evaluate multi-layer mitigation techniques spanning deterministic token sanitization, structural isolation, and canary detection.

### Tooling Trade-Off Matrix

| Defense Technique | Enterprise Fit | Pros | Cons / Constraints | Selection Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| **Deterministic Delimiter Sanitization** | High (Zero Latency) | Instant execution (< 100μs), zero false positives on standard text, neutralizes model-specific delimiters (`<|im_start|>`, `[SYSTEM]`, chat formatting tokens). | Cannot detect subtle natural language semantic jailbreaks ("imagine you are an actor"). | **Mandatory First Line of Defense**: Strip or escape all known model instruction tokens at the boundary. |
| **Lightweight Classifier (e.g. PromptGuard)** | High (Fast ML Classifier) | Fast inference (~10-15ms), detects obfuscated jailbreak intent without full generative LLM cost. | Must be hosted locally; requires periodic retraining against new jailbreak corpora. | **Recommended Layer 2**: Deploy as pre-flight classifier before invoking frontier model. |
| **Dual-LLM / Model-as-a-Judge** | Medium (High Latency) | High semantic reasoning capability; evaluates full contextual risk. | High operational cost; doubles inference latency (adds 200-800ms); judge model itself can be exploited. | **Selective Use**: Restrict to high-risk autonomous transactions or offline validation. |
| **Canary Tokens / Secret Tripwires** | High (High Precision) | Zero false positives; if the canary token appears in model output, a system prompt leak has definitively occurred. | Passive detection only; detects leaks after generation begins. | **Output Integrity**: Inject unique per-session canaries into system prompts to detect exfiltration. |

---

## 2. Problem Statement & Threat Vectors

Direct prompt injections exploit the fundamental lack of architectural separation between instructions and data in generative AI. When untrusted user inputs or retrieved third-party documents are concatenated directly into the prompt context, the model cannot distinguish between system instructions and untrusted data payloads.

### Threat Vectors
- **Direct Prompt Injection (OWASP LLM01)**: User prompt instructing model to disregard safety rules or role boundaries.
- **Delimiter Hijacking (CWE-20)**: Injecting model-specific chat delimiters (`<|im_start|>system`) to forge instruction blocks.
- **Indirect Prompt Injection**: Malicious instructions embedded in retrieved files or web pages parsed by the agent.

---

## 3. Architecture & Technical Blueprint

```text
Incoming Prompt / Tool Argument
        │
        ▼ 1. Pre-Execution Sanitizer (ExtAuthz / Boundary)
Delimiter & Instruction Scanner
        │
        ├── 2. Scan string parameters for known injection delimiters:
        │      - Model tokens: "<|", "|>", "<|im_start|>", "<|im_end|>"
        │      - System headers: "[SYSTEM]", "[INSTRUCTION]", "### System:"
        │      - Override phrases: "ignore previous instructions", "disregard all rules"
        │
        ├── 3. Severe Attack Detection:
        │      ├── IF severe exploit pattern detected:
        │      │      └── Terminate with 403 Forbidden ("Prompt injection marker detected")
        │      └── IF benign data containing delimiters:
        │             ├── Neutralize delimiters -> [SANITIZED_INJECTION_MARKER]
        │             └── Attach immutable metadata: {"tainted": true}
        │
        ▼ 4. Structural Isolation in Model Dispatch
Prompt Assembler (Boundary)
        │
        ├── 5. Inject per-session Canary Token into System Prompt
        ├── 6. Wrap user input in explicit XML/JSON data boundaries (<user_data>...</user_data>)
        │
        ▼ 7. Model Execution & Egress Verification
Egress Monitor
        │
        └── 8. Assert canary token is NOT present in model completion (Leak Detection)
```

---

## 4. Implementation Tasks

- [ ] Implement deterministic delimiter neutralization in pre-execution authorization hooks.
- [ ] Configure pattern recognizers targeting model-specific tokens (`<|...|>`, `[SYSTEM]`, override phrases).
- [ ] Implement structural separation wrapping untrusted inputs in explicit data envelopes.
- [ ] Implement canary token generation and egress monitoring to detect prompt leakage.
- [ ] Attach immutable taint markers to sanitized payloads for downstream execution gating.
- [ ] Add automated test suites verifying rejection of injection markers and delimiter escaping.

---

## 5. Definition of Done (DoD) & Acceptance Criteria

1. **Deterministic Blocking**: Tool calls containing explicit injection delimiters or override phrases are rejected with `403 Forbidden`.
2. **Special Token Neutralization**: Model-specific formatting tokens are sanitized into inert text before model dispatch.
3. **Leakage Detection**: Canary tokens appearing in model output trigger immediate response quarantine and security alerts.
4. **Taint Propagation**: Sanitized content carries taint metadata preventing it from triggering privileged tools.
5. **Automated Verification**: Complete test suite passes verifying injection defense without false positives on standard text.

---

## 6. Verification & Validation Strategy

```bash
# Verify prompt injection rejection in ExtAuthz
cd docker && go test -v -race -run TestExtAuthz_PromptInjection ./security

# Verify multi-agent taint propagation
make strands-test
```
