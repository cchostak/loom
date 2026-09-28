# Comprehensive Threat Model Report

**Generated**: 2026-09-28 12:01:39
**Current Phase**: 9 - Output Generation and Documentation
**Overall Completion**: 100.0%

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Business Context](#business-context)
3. [Classification Profiles](#classification-profiles)
4. [System Architecture](#system-architecture)
5. [Threat Actors](#threat-actors)
6. [Trust Boundaries](#trust-boundaries)
7. [Assets and Flows](#assets-and-flows)
8. [Threats](#threats)
9. [Mitigations](#mitigations)
10. [Assumptions](#assumptions)
11. [Phase Progress](#phase-progress)
12. [Appendix: Reference Catalogue (Not Reviewed)](#appendix-reference-catalogue-not-reviewed)

## Executive Summary

Loom is an enterprise-grade AI security gateway, Model Context Protocol (MCP) containment boundary, and multi-agent governance platform providing zero-trust edge authentication, deep schema and cryptographic validation, and telemetry compliance normalization.

### Key Statistics

- **Total Threats**: 8
- **Total Mitigations**: 8
- **Total Assumptions**: 0
- **System Components**: 8
- **Assets**: 5
- **Threat Actors**: 1
- **Pre-loaded catalogue entries never assessed**: 12 (listed in the appendix, excluded from the counts above)

## Business Context

**Description**: Loom is an enterprise-grade AI security gateway, Model Context Protocol (MCP) containment boundary, and multi-agent governance platform providing zero-trust edge authentication, deep schema and cryptographic validation, and telemetry compliance normalization.

### Business Features

- **Industry Sector**: Technology
- **Data Sensitivity**: Confidential
- **User Base Size**: Large
- **Geographic Scope**: Global / Transboundary
- **Regulatory Requirements**: CCPA / CPRA, SOX, GDPR
- **System Criticality**: High
- **Financial Impact**: High
- **Authentication Requirement**: Federated
- **Deployment Model**: Hybrid cloud
- **User Base Metric**: Organizational customers
- **Revenue Band**: Enterprise
- **Data Residency**: Global / Transboundary
- **Compute Location**: Multi-Continental / International
- **User Base Location**: Global / Transboundary
- **Organizational HQ**: National / Single-Country

## Classification Profiles

### Software Profile

- **Software Type**: AI / ML System
- **Deployment Model**: Hybrid cloud
- **Architecture Style**: Microservices
- **Platform / Runtime**: Container
- **User Domain**: Security
- **Licensing / Ownership**: Internal custom-built
- **Modern Paradigms**: Cloud-native, Containerized, Zero Trust architecture, Agentic AI, AI/ML
- **Description**: Enterprise AI security gateway, Model Context Protocol (MCP) tool sandbox, and OpenTelemetry compliance pipeline.

### Data Asset Profiles

| ID | Name | Asset | Category | Content Types | Sensitivity | Compliance | States | Volume | Lifecycle | Business Domain | Description |
|---|---|---|---|---|---|---|---|---|---|---|---|
| DP001 | Prompts & Model Completions | data-prompts | Unstructured Data | PII, Intellectual property / trade secrets, Operational / telemetry data | Confidential | GDPR, CCPA / CPRA | In transit, In use | Big data | Active | Engineering | User input prompts and upstream model completion payloads containing potential PII, intellectual property, or code. |
| DP002 | MCP Contracts & Signing Keys | data-mcp-keys | Secrets and Credentials | Authentication credentials, Intellectual property / trade secrets | Restricted | SOX | At rest, In use | Small | Active | Operations | Ed25519 signing private/public keys and signed tool_contract.json defining allowed MCP tools and capabilities. |
| DP003 | Audit Telemetry & Finding Ledger | data-telemetry | Structured Data | System metadata, Operational / telemetry data | Internal | GDPR, SOX | At rest, In transit | Medium | Active | Legal | Normalized OpenTelemetry spans and UnifiedFinding governance audit logs stored in hash-chained SQLite/Postgres. |
| DP004 | RAG Vector Embeddings & ACLs | data-vector-embeddings | Semi-Structured Data | Intellectual property / trade secrets, Operational / telemetry data | Confidential | GDPR, CCPA / CPRA | At rest, In use | Medium | Active | Engineering | Vector chunk embeddings and document-level security ACL metadata for enterprise RAG retrieval. |
| DP005 | Tenant Quotas & FinOps Budgets | data-budgets | Structured Data | Operational / telemetry data, PCI / financial data | Internal | None | At rest, In use | Small | Active | Finance | Tenant and workload token and dollar budget counters stored in persistent database. |

### User Personas

| ID | Persona | Name | Privilege | Affiliation | Roles | Intent | Entity Type | Authentication | Threat Actor Overlay | In Scope | Description |
|---|---|---|---|---|---|---|---|---|---|---|---|
| UP001 | Authenticated Standard User | Enterprise Business User | Medium | Employee | End User | Legitimate | Human | OAuth | N/A | Yes | Enterprise employee or developer accessing AI models and agent workflows via corporate IdP. |
| UP002 | Non-Human Identity / Service Account | Strands Agent Swarm Worker | Low | Employee | Service Account | Legitimate | Non-Human | Certificate | N/A | Yes | Autonomous agent instances executing multi-step tasks, tool calls, and inter-agent delegations with ephemeral credentials. |
| UP003 | Auditor / Compliance User | Security & Compliance Auditor | Elevated | Employee | Auditor | Legitimate | Human | Token | N/A | Yes | Corporate security engineer or compliance officer inspecting audit trails and finding queues. |
| UP004 | Anonymous / Unauthenticated User | Adversarial Prompt Injector | None | Public / Unknown | End User | Malicious | Human | None | N/A | Yes | External adversary attempting direct/indirect prompt injection, jailbreaks, parameter tampering, or budget exhaustion. |

### Non-Functional Requirements

- **Time Behaviour**: Responsive — Edge gateway must inspect tokens and enforce ExtAuthz checks within millisecond latency budgets.
- **Availability**: 99.99% — Perimeter security gateway must be highly available for upstream inference traffic.
- **Fail-Safe Behaviour**: Revert to safe state — Security boundary must fail closed on missing credentials, tripped circuits, or unverified contracts.
- **Safety Criticality**: Safety-related — Protects against prompt injection, model jailbreaks, and unauthorized code execution.
- **Interoperability**: Standards-based — Integrates with OpenID Connect, SPIFFE/SPIRE, Envoy ExtAuthz, and OpenTelemetry.
- **Modularity**: High — Decoupled edge gateway, ExtAuthz server, SafeFS sandbox, and telemetry normalizer.
- **User Error Protection**: Strong — Rejects malformed tool calls, invalid schemas, and path traversal attempts.

## System Architecture

### Components

| ID | Name | Type | Service Provider | Description |
|---|---|---|---|---|
| C001 | AgentGateway | Security | CNCF | Perimeter API gateway handling OIDC JWT claim verification, token rate limiting, dollar budgets, and initial CEL tool allowlisting. |
| C002 | ExtAuthzService | Security | Hybrid | Control plane gRPC External Authorization server on port 9001 performing deep JSON schema validation, Ed25519 contract verification, path traversal checks, and prompt injection detection. |
| C003 | SafeFSServer | Container | Hybrid | MCP SafeFS tool container running descriptor-relative openat filesystem operations with O_NOFOLLOW sandboxing under /workspace. |
| C004 | GuardrailProxy | Security | Hybrid | Bidirectional DLP proxy evaluating prompts and completions with Presidio PII redaction and secret scanning. |
| C005 | OTelCollector | Analytics | CNCF | OpenTelemetry Collector Contrib with OTTL privacy transforms stripping raw prompt text and preserving GenAI attributes. |
| C006 | NormalizerService | Analytics | Hybrid | Telemetry normalization service ingesting OTel trace spans, injecting SPIFFE workload identity, and outputting UnifiedFinding audit records. |
| C007 | StrandsSwarmRunner | Compute | Hybrid | Multi-agent swarm execution orchestrator running role-scoped agent tasks with ephemeral credentials and taint lineage. |
| C008 | ExternalLLMProvider | Other | Other | Upstream frontier model APIs (OpenRouter, OpenAI, Anthropic) executing model inference. |

### Connections

| ID | Source | Destination | Protocol | Port | Encrypted | Description |
|---|---|---|---|---|---|---|
| CN001 | StrandsSwarmRunner (C007) | AgentGateway (C001) | HTTPS | 8080 | Yes | Agent calls model and tools via gateway with Bearer JWT. |
| CN002 | AgentGateway (C001) | GatewayBudgetStore (D001) | TCP | N/A | Yes | Gateway queries and updates budget balances in SQLite. |
| CN003 | AgentGateway (C001) | ExtAuthzService (C002) | gRPC | 9001 | Yes | Gateway delegates deep JSON schema, Ed25519 contract, and injection checks to ExtAuthz. |
| CN004 | AgentGateway (C001) | SafeFSServer (C003) | HTTPS | 8084 | Yes | Gateway forwards validated tool calls to SafeFS. |
| CN005 | SafeFSServer (C003) | WorkspaceFileSystem (D003) | Other | N/A | Yes | SafeFS accesses workspace files via descriptor-relative openat syscalls. |
| CN006 | AgentGateway (C001) | GuardrailProxy (C004) | HTTPS | 8082 | Yes | Gateway forwards prompt text to Guardrail proxy for bidirectional PII/secret inspection. |
| CN007 | GuardrailProxy (C004) | ExternalLLMProvider (C008) | HTTPS | 443 | Yes | Sanitized prompt sent to external LLM API for inference. |
| CN008 | AgentGateway (C001) | OTelCollector (C005) | gRPC | 4317 | Yes | AgentGateway exports OTLP trace spans and metrics to collector. |
| CN009 | OTelCollector (C005) | NormalizerService (C006) | HTTP | 8080 | No | OTel collector forwards privacy-scrubbed spans to Normalizer /v1/traces. |
| CN010 | NormalizerService (C006) | NormalizationFindingQueue (D002) | TCP | N/A | Yes | Normalizer writes hash-chained UnifiedFinding records to SQLite queue. |
| CN011 | StrandsSwarmRunner (C007) | VectorStoreRAG (D004) | HTTPS | 6333 | Yes | Agent executes pre-filtered vector search queries with tenant context. |

### Data Stores

| ID | Name | Type | Classification | Encrypted at Rest | Description |
|---|---|---|---|---|---|
| D001 | GatewayBudgetStore | Relational | Internal | Yes | SQLite database storing persistent token and dollar budget counters for AgentGateway. |
| D002 | NormalizationFindingQueue | Relational | Internal | Yes | Hash-chained SQLite database storing normalized UnifiedFinding records for compliance audits. |
| D003 | WorkspaceFileSystem | File System | Confidential | Yes | Target workspace filesystem sandboxed by SafeFS at /workspace. |
| D004 | VectorStoreRAG | NoSQL | Confidential | Yes | Vector database storing embedding chunks with Document-Level Security (DLS) ACL metadata. |

## Threat Actors

### Adversarial Prompt Injector & Agent Hijacker

- **Type**: External Attacker
- **Motivations**: Competitive advantage, Financial gain, Espionage / intelligence collection
- **Resources**: Individual
- **Relationship to Target**: External
- **Sophistication Tier**: Tier 3 - Organized cybercrime
- **State Nexus**: None
- **Targeting Specificity**: Sector-focused
- **Relevant**: Yes
- **Priority**: 1/10
- **Description**: Attacker crafting direct and indirect prompt injections, jailbreaks, and poisoned tool calls to hijack autonomous swarms, exfiltrate confidential enterprise data, and trigger Denial of Wallet.

## Trust Boundaries

### Trust Zones

#### ExternalUntrustedZone

- **Trust Level**: Untrusted
- **Architecture Nodes**: ExternalLLMProvider (C008)
- **Description**: External upstream LLM providers and public internet services.

#### PerimeterDMZZone

- **Trust Level**: Low
- **Architecture Nodes**: AgentGateway (C001), GatewayBudgetStore (D001)
- **Description**: Perimeter API gateway handling client ingress, rate limiting, and dollar budget state.

#### ControlPlaneAndAuditZone

- **Trust Level**: High
- **Architecture Nodes**: ExtAuthzService (C002), GuardrailProxy (C004), OTelCollector (C005), NormalizerService (C006), NormalizationFindingQueue (D002)
- **Description**: Internal zero-trust control plane containing ExtAuthz, Guardrail proxy, OTel collector, and audit ledger.

#### AgentExecutionAndStorageZone

- **Trust Level**: Medium
- **Architecture Nodes**: SafeFSServer (C003), StrandsSwarmRunner (C007), WorkspaceFileSystem (D003), VectorStoreRAG (D004)
- **Description**: Sandboxed agent runners, MCP SafeFS server, and local vector and file stores.

### Trust Boundaries

#### PerimeterIngressBoundary

- **Type**: Network
- **Controls**: OIDC JWT Validation, Rate Limiting, Dollar Budgets, CEL Rules
- **Description**: Perimeter boundary between agent clients and the API gateway.

#### ControlPlaneZeroTrustBoundary

- **Type**: Network
- **Controls**: SPIFFE/SPIRE mTLS, ExtAuthz Inspection, Presidio DLP
- **Description**: Internal zero-trust boundary isolating the control plane microservices.

#### ToolExecutionSandboxBoundary

- **Type**: Container
- **Controls**: SafeFS openat sandboxing, Ed25519 contract verification, gVisor runsc
- **Description**: Sandbox isolation boundary protecting host filesystem and tool execution.

#### ExternalProviderEgressBoundary

- **Type**: Network
- **Controls**: Presidio Egress Redaction, API Key Protection, Circuit Breakers
- **Description**: Egress boundary between Loom internal network and external cloud model providers.

## Assets and Flows

### Assets

| ID | Name | Type | Classification | Lifecycle | Data States | Criticality | Owner |
|---|---|---|---|---|---|---|---|
| A001 | UserPromptAndCompletion | Data | Confidential | N/A | In transit, In use | 4 | N/A |
| A002 | MCPToolContract | Cryptographic Key | Restricted | N/A | At rest, In use | 5 | N/A |
| A003 | AuditFindingsAndTraces | Data | Internal | N/A | At rest, In transit | 3 | N/A |
| A004 | FinOpsBudgetState | Configuration | Internal | N/A | At rest, In use | 3 | N/A |
| A005 | VectorEmbeddings | Data | Confidential | N/A | At rest, In use | 4 | N/A |

### Asset Flows

| ID | Asset | Source | Destination | Protocol | Encrypted | Risk Level |
|---|---|---|---|---|---|---|
| F001 | UserPromptAndCompletion | AgentGateway (C001) | GuardrailProxy (C004) | HTTPS | Yes | 3 |
| F002 | MCPToolContract | AgentGateway (C001) | ExtAuthzService (C002) | gRPC | Yes | 4 |
| F003 | AuditFindingsAndTraces | NormalizerService (C006) | NormalizationFindingQueue (D002) | TCP | Yes | 2 |
| F004 | FinOpsBudgetState | AgentGateway (C001) | GatewayBudgetStore (D001) | TCP | Yes | 2 |
| F005 | VectorEmbeddings | StrandsSwarmRunner (C007) | VectorStoreRAG (D004) | HTTPS | Yes | 3 |

## Threats

### Resolved Threats

#### T1: External Adversary / Malicious User

**Statement**: A External Adversary / Malicious User Ability to submit text prompts to AI model or tools can Crafts adversarial delimiters or role-play framing to override system instructions and invoke unauthorized tools., which leads to Unauthorized execution of administrative tools, data exfiltration, and compromise of agent autonomy.

- **Prerequisites**: Ability to submit text prompts to AI model or tools
- **Action**: Crafts adversarial delimiters or role-play framing to override system instructions and invoke unauthorized tools.
- **Impact**: Unauthorized execution of administrative tools, data exfiltration, and compromise of agent autonomy.
- **Impacted Assets**: A001
- **Tags**: OWASP-LLM01, Prompt-Injection
- **Residual Risk Decision**: Mitigated
- **Residual Severity**: Low
- **Residual Likelihood**: Unlikely
- **Residual Risk Rationale**: Mitigated by ExtAuthz delimiter stripping, injection marker scanning, and structural prompt isolation.
- **Assessment State**: Current

#### T2: Malicious Insider or Compromised CI Build

**Statement**: A Malicious Insider or Compromised CI Build Write access to deployment configuration or tool_contract.json file can Modifies tool descriptions or injects unauthorized tool capabilities without valid cryptographic publisher signature., which leads to Agent invokes weaponized tools resulting in remote code execution or unauthorized system modification.

- **Prerequisites**: Write access to deployment configuration or tool_contract.json file
- **Action**: Modifies tool descriptions or injects unauthorized tool capabilities without valid cryptographic publisher signature.
- **Impact**: Agent invokes weaponized tools resulting in remote code execution or unauthorized system modification.
- **Impacted Assets**: A002
- **Tags**: OWASP-LLM08, Tool-Poisoning
- **Residual Risk Decision**: Mitigated
- **Residual Severity**: Low
- **Residual Likelihood**: Unlikely
- **Residual Risk Rationale**: Mitigated by offline Ed25519 publisher signature verification at boot with fail-closed termination.
- **Assessment State**: Current

#### T3: Adversary exploiting MCP SafeFS tool parameters

**Statement**: A Adversary exploiting MCP SafeFS tool parameters Ability to call read_text_file or write_file tool endpoints can Passes relative traversal paths or creates race-condition symlinks to escape the /workspace sandbox., which leads to Arbitrary file read/write on host container root filesystem, leaking private keys and environment variables.

- **Prerequisites**: Ability to call read_text_file or write_file tool endpoints
- **Action**: Passes relative traversal paths or creates race-condition symlinks to escape the /workspace sandbox.
- **Impact**: Arbitrary file read/write on host container root filesystem, leaking private keys and environment variables.
- **Impacted Assets**: A002
- **Tags**: CWE-22, CWE-59, Path-Traversal
- **Residual Risk Decision**: Mitigated
- **Residual Severity**: Low
- **Residual Likelihood**: Unlikely
- **Residual Risk Rationale**: Mitigated by kernel-enforced descriptor-relative openat resolution with O_NOFOLLOW in SafeFS.
- **Assessment State**: Current

#### T4: Negligent Internal User or Hallucinating Model

**Statement**: A Negligent Internal User or Hallucinating Model Submitting proprietary corporate records or PII into prompt input can Transmits unredacted credit cards, SSNs, or cloud credentials to external public LLM provider, or model regurgitates confidential data., which leads to Regulatory compliance violations (GDPR, PCI-DSS), confidential data leaks, and intellectual property theft.

- **Prerequisites**: Submitting proprietary corporate records or PII into prompt input
- **Action**: Transmits unredacted credit cards, SSNs, or cloud credentials to external public LLM provider, or model regurgitates confidential data.
- **Impact**: Regulatory compliance violations (GDPR, PCI-DSS), confidential data leaks, and intellectual property theft.
- **Impacted Assets**: A001
- **Tags**: OWASP-LLM06, PII-Leakage, DLP
- **Residual Risk Decision**: Mitigated
- **Residual Severity**: Low
- **Residual Likelihood**: Unlikely
- **Residual Risk Rationale**: Mitigated by bidirectional Presidio NLP analysis and deterministic regex secret masking.
- **Assessment State**: Current

#### T5: Recursive Agent Execution Loop or Malicious DoS Attacker

**Statement**: A Recursive Agent Execution Loop or Malicious DoS Attacker Access to trigger multi-agent swarm workflows can Spawns unbounded recursive tool calls or sends flooding prompts that exhaust cloud LLM API tokens and daily dollar spending limits., which leads to Financial loss through runaway cloud API bills, service outage for legitimate enterprise tenants.

- **Prerequisites**: Access to trigger multi-agent swarm workflows
- **Action**: Spawns unbounded recursive tool calls or sends flooding prompts that exhaust cloud LLM API tokens and daily dollar spending limits.
- **Impact**: Financial loss through runaway cloud API bills, service outage for legitimate enterprise tenants.
- **Impacted Assets**: A004
- **Tags**: OWASP-LLM04, Denial-of-Wallet, FinOps
- **Residual Risk Decision**: Mitigated
- **Residual Severity**: Low
- **Residual Likelihood**: Unlikely
- **Residual Risk Rationale**: Mitigated by AgentGateway daily dollar budget hard block ($50/day) and upstream provider circuit breakers.
- **Assessment State**: Current

#### T6: Malicious Tenant User in Multi-Tenant Environment

**Statement**: A Malicious Tenant User in Multi-Tenant Environment Ability to execute RAG semantic search queries can Submits crafted semantic queries that retrieve adjacent tenant vector embeddings due to missing pre-filtering or stale ACLs., which leads to Confidential cross-organizational data leakage, violation of multi-tenant security isolation.

- **Prerequisites**: Ability to execute RAG semantic search queries
- **Action**: Submits crafted semantic queries that retrieve adjacent tenant vector embeddings due to missing pre-filtering or stale ACLs.
- **Impact**: Confidential cross-organizational data leakage, violation of multi-tenant security isolation.
- **Impacted Assets**: A005
- **Tags**: RAG, Vector-DLS, Multi-Tenancy
- **Residual Risk Decision**: Mitigated
- **Residual Severity**: Low
- **Residual Likelihood**: Unlikely
- **Residual Risk Rationale**: Mitigated by mandatory Document-Level Security (DLS) pre-filtering enforced before vector traversal.
- **Assessment State**: Current

#### T7: Privileged Malicious Insider or Compromised Host

**Statement**: A Privileged Malicious Insider or Compromised Host Database access to audit log storage can Modifies or deletes audit finding records to conceal policy violations or unauthorized tool invocations., which leads to Loss of audit non-repudiation, failed regulatory compliance audits (SOC 2, ISO 27001).

- **Prerequisites**: Database access to audit log storage
- **Action**: Modifies or deletes audit finding records to conceal policy violations or unauthorized tool invocations.
- **Impact**: Loss of audit non-repudiation, failed regulatory compliance audits (SOC 2, ISO 27001).
- **Impacted Assets**: A003
- **Tags**: Audit-Ledger, Non-Repudiation, Compliance
- **Residual Risk Decision**: Mitigated
- **Residual Severity**: Low
- **Residual Likelihood**: Unlikely
- **Residual Risk Rationale**: Mitigated by cryptographic SHA-256 hash chaining of UnifiedFinding records in the SQLite queue.
- **Assessment State**: Current

#### T8: Compromised Container Worker in Bridge Network

**Statement**: A Compromised Container Worker in Bridge Network Compromised single container workload can Probes adjacent internal microservices over Docker bridge network without presenting cryptographic workload identity., which leads to Privilege escalation and unauthorized access to control plane and database services.

- **Prerequisites**: Compromised single container workload
- **Action**: Probes adjacent internal microservices over Docker bridge network without presenting cryptographic workload identity.
- **Impact**: Privilege escalation and unauthorized access to control plane and database services.
- **Impacted Assets**: A002, A003, A004
- **Tags**: Zero-Trust, SPIFFE, mTLS
- **Residual Risk Decision**: Mitigated
- **Residual Severity**: Low
- **Residual Likelihood**: Unlikely
- **Residual Risk Rationale**: Mitigated by mandatory TLS 1.3 mTLS with SPIFFE/SPIRE SVIDs limited to <= 10m TTL and peer ACL validation.
- **Assessment State**: Current

## Mitigations

### Resolved Mitigations

#### M1: ExtAuthz Pre-execution Delimiter Neutralization & Prompt Injection Marker Scanning

**Addresses Threats**: T1

#### M2: Ed25519 Publisher Cryptographic Contract Signing and Boot Verification

**Addresses Threats**: T2

#### M3: Kernel-Level Descriptor-Relative Sandboxing (openat, O_NOFOLLOW) in SafeFS

**Addresses Threats**: T3

#### M4: Bidirectional Presidio PII Masking and Deterministic Secret Scrubbing

**Addresses Threats**: T4

#### M5: Durable Dollar Budgets ($50/day block) and Upstream Circuit Breakers

**Addresses Threats**: T5

#### M6: Mandatory Document-Level Security (DLS) Pre-Filtering in Vector Search

**Addresses Threats**: T6

#### M7: Cryptographically Hash-Chained Audit Ledger in Normalizer Service

**Addresses Threats**: T7

#### M8: Zero-Trust SPIFFE/SPIRE Workload Identity with Ephemeral X.509 SVIDs and mTLS

**Addresses Threats**: T8

## Assumptions

*No assumptions defined.*

## Phase Progress

| Phase | Name | Completion |
|---|---|---|
| 1 | Business Context Analysis | 100% ✅ |
| 2 | Architecture Analysis | 100% ✅ |
| 3 | Threat Actor Analysis | 100% ✅ |
| 4 | Trust Boundary Analysis | 100% ✅ |
| 5 | Asset Flow Analysis | 100% ✅ |
| 6 | Threat Identification | 100% ✅ |
| 7 | Mitigation Planning | 100% ✅ |
| 7.5 | Code Validation Analysis | 100% ✅ |
| 8 | Residual Risk Analysis | 100% ✅ |
| 9 | Output Generation and Documentation | 100% ✅ |

## Appendix: Reference Catalogue (Not Reviewed)

The server pre-loads common threat actors as a starting point. Entries that were never assessed for this system are not part of the threat model and are listed here only as reference.

### Threat Actors (12 not reviewed)

- **TA001** - Insider
- **TA002** - External Attacker
- **TA003** - Nation-state Actor
- **TA004** - Hacktivist
- **TA005** - Organized Crime
- **TA006** - Competitor
- **TA007** - Script Kiddie
- **TA008** - Disgruntled Employee
- **TA009** - Privileged User
- **TA010** - Third Party
- **TA011** - Terrorist Organization
- **TA012** - Private Sector Offensive Actor

---

*This threat model report was generated automatically by the Threat Modeling MCP Server.*
