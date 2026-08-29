# Security Policy — Loom Cloud Development Platform

The Loom maintainers and platform engineering team take security seriously. We welcome responsible disclosure of vulnerabilities discovered across our core gateway, guardrail proxy, container images, and deployment configurations.

---

## 1. Supported Versions

Security updates, vulnerability patches, and configuration fixes are actively provided for the following versions:

| Version | Supported | Notes |
| :--- | :--- | :--- |
| `1.x` / `main` | :white_check_mark: | Active production release branch |
| `< 1.0` | :x: | Legacy scaffold versions; upgrade recommended |

---

## 2. Reporting a Vulnerability

If you discover a security vulnerability, **please do not disclose it publicly or open a public GitHub issue**.

### Reporting Channels

- **Email**: Submit reports to [security@platform.internal](mailto:security@platform.internal) (or your designated platform security team email).
- **GitHub Private Advisory**: Open a Private Security Advisory under the repository's **Security** tab -> **Report a vulnerability**.

### Information to Include in Your Report

To help us investigate and triage the issue quickly, please provide:
1. **Description**: Clear summary of the issue and potential impact.
2. **Affected Component**: Affected service (e.g., `guardrail-proxy`, `agentgateway`, `code-server`, or configuration).
3. **Reproduction Steps**: Detailed proof-of-concept (PoC) steps or script reproducing the vulnerability.
4. **Environment**: Operating system, Docker engine version, and architecture.
5. **Mitigation Suggestion**: Any proposed patches or workarounds (if available).

---

## 3. Vulnerability Response Timeline & SLAs

| Phase | Target SLA | Description |
| :--- | :--- | :--- |
| **Initial Acknowledgment** | **< 24 hours** | Confirmation that the report was received and assigned to an engineer |
| **Severity Assessment** | **< 48 hours** | Triage, CVSS score calculation, and determination of exploitability |
| **Fix & Remediation** | **< 7 business days** | Patch development, regression testing, and build verification |
| **Public Release / Advisory**| Coordinated | Release of updated container images and security bulletin |

---

## 4. Security Architecture & Trust Boundaries

The Loom platform enforces multi-layered defense-in-depth:

```
[Developer Client / Web IDE]
              │ (HTTP / JSON)
              ▼
    [Agentgateway Proxy]
       │             │
 (Pre-Execution)     │ (Allowed Request)
       ▼             ▼
[Guardrail Proxy]  [Upstream LLM Provider (OpenRouter)]
 (403 Blocked /    [Model Context Protocol (MCP) Tools]
  200 Allowed)       │ (Enforced by CEL Authorization Policy)
                     ▼
             [Workspace Container]
```

### Key Security Invariants
- **Synchronous Guardrail Interception**: All LLM queries are inspected synchronously before upstream dispatch. Destructive commands (`sudo`, `rm -rf`, fork bombs, system file reads) are blocked with `403 Forbidden`.
- **CEL Default-Deny MCP Tool Authorization**: Model Context Protocol tool execution requires explicit allow-listing via Common Expression Language (CEL). Unmatched tools evaluate to `deny`.
- **Network Isolation**: Inter-container communication is bound to the isolated internal `ide-net` Docker bridge. External access is strictly controlled via defined host port bindings.
- **Least-Privilege Secret Isolation**: API keys (`OPENROUTER_API_KEY`) and authentication credentials are injected via environment variables and never baked into container images or logged.

---

## 5. Safe Harbor

We consider security research conducted under this policy to be:
- Authorized under applicable anti-hacking laws (e.g., CFAA).
- Protected from legal action, provided researchers act in good faith, avoid privacy violations, do not degrade production infrastructure, and provide reasonable time for remediation before disclosure.
