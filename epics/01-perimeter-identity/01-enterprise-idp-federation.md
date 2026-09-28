# TASK-PI-01: Enterprise IdP Federation & JWT Claim Validation

## Epic: 01-perimeter-identity
**Status**: Ready for Implementation  
**Security Classification**: Critical (Perimeter Ingress Authentication)  
**Relevant Standards**: OpenID Connect Core 1.0, OAuth 2.0 (RFC 6749), PKCE (RFC 7636), NIST SP 800-63C  

---

## 1. Context & Tooling Evaluation

Enterprise deployments never rely on self-hosted toy identity providers for production authentication. Major corporate environments already have established corporate Identity Providers (IdPs) enforcing single sign-on (SSO), multi-factor authentication (MFA), and conditional access policies.

The AI Gateway perimeter must federate seamlessly with existing enterprise identity infrastructure using standard OpenID Connect (OIDC) Discovery and JSON Web Key Sets (JWKS).

### Tooling Trade-Off Matrix

| Identity Solution | Enterprise Fit | Pros | Cons / Constraints | Selection Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| **Microsoft Entra ID (Azure AD)** | High (Dominant in Fortune 500) | Native Azure integration, robust Conditional Access policies, automated SCIM provisioning, managed service accounts. | Complex tenant administration; graph API permission overhead. | **Primary Production Option** for enterprise environments with Microsoft/M365 footprints. |
| **Okta Workforce Identity** | High (Industry standard SaaS IdP) | Rich API Access Management, fine-grained OAuth scopes, client credentials grant support, universal directory. | High licensing costs; enterprise tier required for custom authorization servers. | **Primary Production Option** for cloud-first and multi-cloud enterprise deployments. |
| **Ping Identity (PingFederate / PingOne)** | High (Financial & Banking standard) | High performance in regulated on-premise/hybrid environments, advanced claims transformation. | Complex deployment topology; steeper operational learning curve. | **Supported Option** for high-compliance banking/insurance data environments. |
| **Keycloak / Dex** | Low (Dev / CI Mock Only) | Lightweight, open-source, easily containerized in Docker Compose for headless integration testing. | Lacks enterprise MFA, conditional access, centralized directory governance, and compliance certifications. | **CI/Dev Mock Only**: Retain lightweight OIDC container exclusively for automated local test suites. |

---

## 2. Problem Statement & Threat Vectors

Static developer API keys and long-lived bearer tokens present severe security vulnerabilities: credential theft, lack of individual accountability, and impossible revocation. Every interaction with an enterprise AI gateway—whether by human engineers, automated CI pipelines, or external partner workloads—must be authenticated against the enterprise IdP.

### Threat Vectors
- **Credential Theft & Impersonation (OWASP LLM08 / CWE-287)**: Stolen static tokens reused across boundaries without MFA or revocation checks.
- **Audience Confusion & Cross-Service Relay (CWE-290)**: Using tokens intended for one internal service to access sensitive model inference endpoints.
- **Token Expiration & Clock-Skew Exploitation (CWE-613)**: Exploiting lax expiration checks on distributed nodes to replay stale credentials.

---

## 3. Architecture & Technical Blueprint

```text
User / Developer / Partner Application
        │
        ▼ 1. Authenticate via OAuth 2.0 PKCE / Client Credentials
Enterprise IdP (Entra ID / Okta / PingFederate)
        │
        ▼ 2. Issue Signed JWT Access Token (RS256, <= 15m TTL)
AI Security Gateway (Edge Perimeter)
        │
        ├── 3. Dynamic JWKS retrieval from IdP /.well-known/openid-configuration
        ├── 4. Validate signature, issuer (iss), audience (aud), and expiration (exp)
        ├── 5. Common Expression Language (CEL) Claim Policy:
        │      - Assert issuer matches enterprise IdP URL
        │      - Assert subject (sub) is non-empty
        │      - Assert tenant_id in authorized organization list
        │      - Map IdP groups/roles into gateway context
        │
        ├── 6. Invert identity into trusted internal headers:
        │      - X-Principal: <claims.sub>
        │      - X-Tenant-ID: <claims.tenant_id>
        │      - X-Roles: <claims.roles>
        │
        ▼ 7. Forward authenticated context to ExtAuthz / Backend Workload
```

---

## 4. Implementation Tasks

- [ ] Define standard OIDC configuration schema supporting dynamic enterprise issuer discovery and pinned JWKS caches.
- [ ] Implement Common Expression Language (CEL) rules for edge claim validation (`iss`, `aud`, `sub`, `exp`, `tenant`).
- [ ] Implement secure header injection (`X-Principal`, `X-Tenant-ID`, `X-Roles`) for authenticated downstream propagation.
- [ ] Implement fail-closed rejection returning `401 Unauthorized` for missing, expired, or invalid tokens.
- [ ] Configure local containerized OIDC mock (Dex/Keycloak) strictly for headless automated CI pipelines.
- [ ] Write integration test harness simulating Entra ID / Okta JWTs with realistic claims and signature verification.

---

## 5. Definition of Done (DoD) & Acceptance Criteria

1. **Protocol Compliance**: Gateway successfully validates JWT tokens issued by standard enterprise IdPs (Entra ID, Okta) using standard OIDC discovery endpoints.
2. **Fail-Closed Standard**: Requests lacking a valid Bearer token or presenting expired/tampered tokens are rejected at the edge with `401 Unauthorized`.
3. **Audience & Issuer Isolation**: Tokens issued for unauthorized audiences or mismatched issuers are denied with `403 Forbidden`.
4. **Context Propagation**: Validated user identity and tenant attributes are injected into downstream request headers for audit attribution.
5. **Automated Verification**: Headless CI tests pass against containerized OIDC test fixture without external internet dependencies.

---

## 6. Verification & Validation Strategy

```bash
# Verify gateway configuration and claim validation schemas
make check

# Run automated OIDC claim evaluation test suite
cd docker && go test -v -run TestOIDCClaimValidation ./...
```
