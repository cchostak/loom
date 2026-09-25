# Enterprise AI Security Problem & Mitigation Matrix

This matrix maps AI security risks, vulnerabilities, and threats (aligned with OWASP Top 10 for LLMs, MITRE ATLAS, and NIST AI RMF) to production tooling and proven architectural methodologies.

---

## 1. Problem / Tooling / Methodology Matrix

| # | Threat / Problem | Tooling to Fix | Methodology to Fix | Loom Reference |
|---|:---|:---|:---|:---|
| **01** | **Prompt Injection (Direct & Jailbreaks)**<br/>Adversarial inputs manipulate LLM into ignoring system directives or safety instructions. | Presidio, Agentgateway, Llama Guard, NeMo Guardrails, regex filters | **Multi-tier defense-in-depth**: Fast regex pattern detection + semantic guardrail classifier. Strip control tokens (`<\|...\|>`) and reject non-printable characters. | [`guardrail-proxy/`](docker/cmd/guardrail-proxy/), [`mcp.py`](integrations/strands/loom_strands/mcp.py) |
| **02** | **Tool Poisoning & Schema Tampering**<br/>Compromised or rogue MCP tools inject instructions via manipulated descriptions or schemas. | Python JSON Schema, Ed25519 signing keys, MCP Interceptor | **Cryptographic Contract Sealing**: Sign tool contract offline. Validate tool schemas dynamically; terminate session on schema mutation or injection markers. | [`mcp.py`](integrations/strands/loom_strands/mcp.py), [`tool_contract.json`](integrations/strands/loom_strands/tool_contract.json) |
| **03** | **Excessive Agency & Arbitrary Tool Use**<br/>Autonomous agent invokes destructive tools or unauthorized API endpoints. | Agentgateway CEL policies, Open Policy Agent (OPA), `security.Policy` | **Principle of Least Privilege**: Explicit allowlist per agent role/workload. Context-aware CEL matching method, tool, and tenant; default-deny on unlisted tools. | [`config/policy.json`](config/policy.json), [`policy.go`](docker/security/policy.go) |
| **04** | **Directory Traversal & Symlink Escape**<br/>Agent reads `/etc/passwd` or escapes container boundaries via `../` or symlinks. | SafeFS, Linux kernel syscalls (`openat2`, `O_NOFOLLOW`), gVisor | **Kernel-Level Sandboxing**: Descriptor-relative path resolution preventing traversal; block symlinks and canonicalize paths strictly under `/workspace`. | [`safefs/`](docker/safefs/), [`docker-compose.isolation.yml`](docker-compose.isolation.yml) |
| **05** | **Agent Impersonation & Rogue Swarms**<br/>Lateral movement or compromised container impersonating another agent in a swarm. | SPIFFE/SPIRE, mTLS (TLS 1.3), X.509 SVIDs, Docker metadata relay | **Zero-Trust Workload Identity**: Ephemeral cryptographic identities ($\le$ 10m TTL) attested by container runtime. Require mTLS for all A2A and boundary links. | [`workload.go`](docker/security/workload.go), [`config/spire/`](config/spire/) |
| **06** | **Denial of Wallet & Recursive Swarm Loops**<br/>Infinite agent loops or runaway queries exhaust LLM API credits and compute. | Token Bucket Rate Limiters, Sliding Window Budgets | **Bounded Execution Quotas**: Hard admission limits on RPM, tokens per session, concurrent operations, and workflow lifetime. Fail fast with 429. | [`budget.go`](docker/security/budget.go) |
| **07** | **Cascading Failures from Provider Outages**<br/>Slow or failing upstream model APIs cause thread starvation and cascading latency. | Go `security.Circuit`, Envoy / Agentgateway Circuit Breaker | **Automated Circuit Breaking**: Track consecutive upstream failures (5xx/timeouts). Trip to `OPEN` on 3 failures; reject calls with 503 for 30s cooldown. | [`circuit.go`](docker/security/circuit.go) |
| **08** | **Sensitive Data Disclosure (PII / Secrets)**<br/>Proprietary records, SSNs, or API keys leaked via user prompts or model completions. | Microsoft Presidio Analyzer, Gitleaks, regex pattern scrubber | **Synchronous Bidirectional Inspection**: Inspect input prompts and model outputs. Redact or reject requests with 403 on detected PII/secret leaks. | [`guardrail-proxy/`](docker/cmd/guardrail-proxy/), [`server.go`](docker/boundary/server.go) |
| **09** | **Compliance Gaps & Non-Auditable Actions**<br/>Security events fragmented across logs, unable to satisfy SOC 2, ISO 27001, or EU AI Act. | OpenTelemetry Collector Contrib, SQLite, BlackShield schema | **Telemetry Normalization**: Transform guardrail events via OTel into unified compliance findings (`policy_violation`, `posture_drift`) in a queryable queue. | [`normalizer.go`](docker/enterprise/normalizer.go), [`otel-collector-config.yaml`](config/otel-collector-config.yaml) |
| **10** | **Identity Federation & Key Sprawl**<br/>Static hardcoded tokens distributed to developers and CI pipelines. | Dex OIDC Provider, OAuth 2.0 PKCE, JWKS validation | **Centralized Ephemeral Auth**: Short-lived JWT access tokens issued via PKCE/Client Credentials; validate tokens against pinned JWKS and issuer claims. | [`docker-compose.dex.yml`](docker-compose.dex.yml), [`bootstrap_dex.py`](scripts/bootstrap_dex.py) |
| **11** | **Cross-Tenant Vector Data Leakage (RAG)**<br/>Embedding retrieval returns chunks belonging to other tenants or unauthorized ACLs. | Qdrant, Milvus, pgvector, Metadata Pre-filtering | **Document-Level Security (DLS)**: Pre-filter vector searches strictly by `tenant_id` and user ACLs before calculating cosine similarity. | [`docs/enterprise-lab.md`](docs/enterprise-lab.md), [`1.md`](epics/tasks/1.md) |
| **12** | **Indirect Prompt Injection in Knowledge Base**<br/>Ingested documents (PDFs, filings) contain hidden adversarial instructions. | Text extraction sandbox, gVisor, content sanitizers | **Ingestion Quarantine & Taint Tracking**: Parse documents in isolated micro-VMs; tag retrieved contexts with immutable taint markers (`tainted=true`). | [`connection.py`](integrations/strands/loom_strands/connection.py), [`mcp.py`](integrations/strands/loom_strands/mcp.py) |

---

## 2. Architectural Methodology Breakdown

### Defense-in-Depth Principle
Never rely on a single layer (e.g., prompt filtering alone). Loom applies security across four concentric layers:
1. **Network & Runtime Boundary**: gVisor sandbox (`runsc`), internal Docker bridges, SPIFFE mTLS mesh.
2. **Ingress API Gateway**: Dex OIDC / Bearer authentication, CEL attribute policies, session rate budgets, circuit breakers.
3. **Execution Context Layer**: Strict JSON Schema enforcement, Ed25519 signed MCP contracts, descriptor-relative `safefs` syscall sandboxing.
4. **Governance & Observability**: OpenTelemetry attribute filtering, BlackShield Unified Finding normalization, hash-chained audit trails.

### Fail-Closed Standard
When any security dependency is unavailable (Presidio down, SPIRE socket unreachable, OIDC issuer timeout, circuit tripped, policy malformed), Loom's policy boundary **fails closed**—denying access immediately rather than silently bypassing controls.

---

## 3. Verification & Validation Commands

All mechanisms listed in this matrix are verifiable via automated test suites:

```bash
# Verify MCP schema validation, Ed25519 signing & poisoning defenses
make mcp-test

# Verify Workload Identity, SVID expiration & SPIFFE ACL enforcement
cd docker && go test -v -race -run 'TestWorkload|TestSVID' ./security

# Verify Session token budgets, concurrency limits & circuit breakers
cd docker && go test -v -race -run 'TestBudget|TestCircuit' ./security

# Verify Telemetry normalization & BlackShield finding queue
make test-telemetry

# Run complete cross-language verification suite
make test-all
```
