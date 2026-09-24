# Security Policy — Loom Cloud Development Platform

The Loom maintainers and platform engineering team take security seriously. We welcome responsible disclosure of vulnerabilities discovered across our core gateway, guardrail proxy, container images, and deployment configurations.

---

## 1. Supported Versions

Security updates, vulnerability patches, and configuration fixes are actively provided for the following versions:

| Version | Supported | Notes |
| :--- | :--- | :--- |
| `1.x` / `main` | :white_check_mark: | Active development branch |
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

## 4. Runtime boundaries and limitations

This repository is a local developer deployment. Read the
[threat model](docs/security-threat-model.md), [implementation evidence](docs/security-implementation.md)
and [remaining production work](docs/security-roadmap.md) before deployment.

Client traffic now enters an authenticated control plane before Agentgateway.
Versioned policy checks actor/workload/resource/destination context. Agentgateway
retains request/response hooks and CEL default deny. MCP execution is limited to
two bounded read-only operations; OS descriptor traversal rejects symlinks.
Detection failure denies model dispatch and ingestion promotion.

All host ports bind to loopback; raw gateway, guardrail and OTLP services are
internal. Core containers run as non-root with dropped capabilities, read-only
roots and resource limits. The IDE remains a writable development environment.
Provider credentials are held by Agentgateway, not by the filesystem child's
environment. A compromised gateway can still misuse its own provider credential.

Security events contain server-generated trace/decision IDs, policy reasons and
action digests, never raw request bodies/arguments. Local audit storage is not
immutable. Collector attribute suppression does not protect a compromised host
or collector. Detector success does not prove that content contains no secrets.

Security CI blocks HIGH/CRITICAL dependency and image findings. Exceptions need
a reviewed issue containing the exact finding, owner, rationale, compensating
control and expiry; there are no blanket ignore-unfixed or allow-failure settings.
Update immutable image/action references through reviewed dependency PRs, rebuild,
scan and rerun runtime tests. OCI SBOM/provenance metadata is generated in CI;
signature verification before deployment remains required production work.

---

## 5. Safe Harbor

We consider security research conducted under this policy to be:
- Authorized under applicable anti-hacking laws (e.g., CFAA).
- Protected from legal action, provided researchers act in good faith, avoid privacy violations, do not degrade production infrastructure, and provide reasonable time for remediation before disclosure.
