# TASK-PI-02: Workload Identity & Ephemeral mTLS Transport Security

## Epic: 01-perimeter-identity
**Status**: Ready for Implementation  
**Security Classification**: Critical (Internal Transport & Workload Authentication)  
**Relevant Standards**: SPIFFE, SPIRE, RFC 8446 (TLS 1.3), NIST SP 800-207 (Zero Trust Architecture)  

---

## 1. Context & Tooling Evaluation

In multi-agent swarms and distributed microservices, network segmentation alone does not provide zero-trust security. Container networks require cryptographic service identity to prevent lateral movement and unauthorized tool access.

### Tooling Trade-Off Matrix

| Workload Identity Solution | Architecture Fit | Pros | Cons / Constraints | Selection Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| **SPIFFE / SPIRE** | High (Cloud-Native Standard) | Platform-agnostic, kernel/container attestation (Docker/K8s), short-lived X.509 SVIDs ($\le 10$m), automated rotation. | Requires running SPIRE server/agent daemons; initial configuration complexity. | **Selected Standard**: Enables uniform cryptographic identity across containerized local labs, hybrid cloud, and Kubernetes. |
| **Service Mesh (Istio / Linkerd)** | Medium (Kubernetes Focused) | Transparent mTLS, automatic sidecar injection, rich traffic routing capabilities. | Excessive operational overhead for lightweight swarm deployments; tightly coupled to Kubernetes. | **Alternative for K8s Platforms**: Recommended if enterprise already operates enterprise Istio mesh. |
| **Cloud IAM Workload Federation** | Medium (Cloud-Specific) | Native integration with AWS IRSA, GCP Workload Identity, or Azure Managed Identities. | Provider lock-in; fails to secure on-premise, local Docker, or cross-cloud agent environments. | **Supplemental**: Use for gateway egress to cloud-managed model endpoints (e.g. AWS Bedrock, Vertex AI). |
| **Static Pinned TLS Certificates** | Low (Legacy) | Simple initial implementation; no daemon infrastructure required. | Severe credential compromise risk, manual rotation toil, lacks dynamic runtime attestation. | **Anti-Pattern**: Do not use in production enterprise deployments. |

---

## 2. Problem Statement & Threat Vectors

If an attacker achieves prompt injection or remote code execution in an untrusted agent container, standard shared network bridges permit lateral movement. Without mutual cryptographic identity, compromised containers can impersonate privileged orchestrators, intercept internal tool traffic, or query administrative APIs.

### Threat Vectors
- **Lateral Movement & Container Impersonation (CWE-287)**: Compromised agent worker calling privileged filesystem or execution endpoints.
- **Internal Eavesdropping & MITM (CWE-319)**: Intercepting sensitive prompt data or tool arguments over plaintext container bridges.
- **Exfiltrated Certificate Replay (CWE-294)**: Using stolen long-lived certificates outside the container execution window.

---

## 3. Architecture & Technical Blueprint

```text
Container Runtime (Docker / containerd / K8s)
        │
        ▼ 1. Node & Workload Attestation (Container PID, labels, service name)
SPIRE Agent Socket (unix:///run/spire/agent.sock)
        │
        ▼ 2. Issue Ephemeral X.509 SVID (TTL <= 10m, URI: spiffe://loom.local/workload/<service>)
Workload Process / Boundary Service
        │
        ├── 3. Enforce TLS 1.3 with Client Certificate (mTLS)
        ├── 4. Evaluate SVID Duration: Assert (NotAfter - NotBefore) <= 10 minutes
        ├── 5. Evaluate Clock Skew: Assert CurrentTime within [NotBefore, NotAfter]
        ├── 6. Extract URI SAN: Assert spiffe://loom.local/workload/<peer> in Peer ACL
        │
        ▼ 7. Bind attested SPIFFE ID to internal request context for audit logging
```

---

## 4. Implementation Tasks

- [ ] Deploy SPIRE Server and Agent infrastructure with container runtime attestation plugins.
- [ ] Implement mTLS listener enforcing TLS 1.3 and mandatory peer certificate verification.
- [ ] Implement Go/Python middleware validating SVID certificate duration ($\le 10$ minutes) and clock validity.
- [ ] Implement SPIFFE ID Access Control List (ACL) verification for sensitive tool endpoints.
- [ ] Bind authenticated SPIFFE identities into telemetry context for end-to-end tracing.
- [ ] Create automated test suite exercising valid SVIDs, expired certificates, unlisted peers, and duration violations.

---

## 5. Definition of Done (DoD) & Acceptance Criteria

1. **Mandatory mTLS**: Plaintext HTTP requests to internal boundaries are rejected with `401 Unauthorized ("mTLS required")`.
2. **Strict SVID Lifetime**: Certificates with validity exceeding 10 minutes are rejected with `403 Forbidden ("SVID lifetime exceeds policy")`.
3. **Peer Authorization**: Clients presenting valid certificates with unlisted SPIFFE IDs are denied access.
4. **Automated Rotation**: Workload SVIDs rotate automatically before expiration without connection interruption.
5. **Test Coverage**: Automated test suite validates expired, forged, and over-duration certificates.

---

## 6. Verification & Validation Strategy

```bash
# Run workload identity and SVID certificate verification tests
cd docker && go test -v -race -run 'TestWorkload|TestSVID' ./security
```
