# TASK-TA-03: Tamper-Evident & Cryptographically Sealed Audit Ledger

## Epic: 06-telemetry-audit-compliance
**Status**: Ready for Implementation  
**Security Classification**: Critical (Non-Repudiation & Tamper-Evident Logging)  
**Relevant Standards**: SOC 2 CC7.2, ISO 27001 (A.12.4.2 Protection of Log Information), EU AI Act Art. 12  

---

## 1. Context & Tooling Evaluation

In regulatory AI governance, audit records must possess cryptographic integrity. Standard database tables and log files can be modified or deleted by privileged database administrators, compromised credentials, or sophisticated adversaries covering their tracks. Tamper-evident logging ensures any record modification or deletion breaks mathematical integrity.

### Tooling Trade-Off Matrix

| Ledger Architecture | Enterprise Fit | Pros | Cons / Constraints | Selection Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| **Cryptographic Hash-Chained RDBMS** | High (Portable & Open) | Embeds SHA-256 hash chaining into standard SQLite/PostgreSQL; zero proprietary vendor dependencies; fast verification; mathematically verifiable by third-party auditors. | Requires implementing hash chain calculation on record insert. | **Selected Baseline Standard**: Deploy hash-chained audit table in local/enterprise database. |
| **Immutable Database (immudb)** | High (Specialized Ledger) | Native Merkle tree proofs, tamper-proof state, high-speed cryptographic verification. | Additional infrastructure component to deploy and manage; operational overhead. | **Enterprise Dedicated Option**: Recommended for dedicated enterprise compliance audit clusters. |
| **WORM Object Storage (S3 Object Lock)** | High (Long-Term Archival) | Regulatory compliance (SEC 17a-4, FINRA); hardware/cloud-enforced immutability; write-once-read-many. | High latency for real-time querying; better suited for daily batch archival than synchronous event logging. | **Long-Term Retention**: Export daily sealed ledger snapshots to WORM object storage. |

---

## 2. Problem Statement & Threat Vectors

Log files and database tables are vulnerable to tampering by privileged insiders, compromised database credentials, or attackers seeking to erase evidence of model exfiltration or policy violations. Without cryptographic immutability, audit logs cannot serve as legal proof in regulatory compliance audits (SOC 2, EU AI Act).

### Threat Vectors
- **Audit Log Tampering / Repudiation (CWE-312 / CWE-353)**: Modifying event logs to hide policy violations or unapproved data access.
- **Selective Log Deletion**: Deleting records of unauthorized tool calls or prompt injection attempts.
- **Privileged Host Tampering**: Root user on database server altering finding records.

---

## 3. Architecture & Technical Blueprint

```text
Event Ingestion / Normalized Finding
        │
        ▼ 1. Enqueue Finding
Audit Ledger Service (docker/enterprise/normalizer.go)
        │
        ├── 2. Retrieve previous record's hash (H_{n-1})
        ├── 3. Canonicalize current finding payload (JSON bytes)
        ├── 4. Compute current record digest:
        │      H_n = SHA-256( H_{n-1} || CurrentFindingPayload || Timestamp )
        │
        ├── 5. Insert Record into normalization_queue:
        │      (id, finding_id, payload, prev_hash, current_hash, timestamp)
        │
        ▼ 6. Audit Verification Run (Periodic or on-demand)
Auditor Verification Tool
        │
        ├── Iterate through ledger from genesis record
        ├── Re-compute H_i = SHA-256(H_{i-1} || Payload_i || Timestamp_i)
        ├── Assert H_i == stored_current_hash
        │      ├── ALL MATCH: Chain Verified (Integrity Intact)
        │      └── MISMATCH: Tampering Detected at Record ID = i
```

---

## 4. Implementation Tasks

- [ ] Implement SHA-256 hash-chaining logic on finding record insertion.
- [ ] Implement cryptographic genesis block initialization and verification.
- [ ] Enforce bearer token authentication on `GET /findings` endpoint.
- [ ] Implement bounded storage capacity (100k records) with FIFO archival to prevent denial of storage.
- [ ] Build automated verification script checking chain integrity from genesis to head.
- [ ] Add automated test suites validating finding persistence, hash calculation, and tamper detection.

---

## 5. Definition of Done (DoD) & Acceptance Criteria

1. **Cryptographic Chaining**: Every persisted finding record contains the hash of the preceding record and a valid current digest.
2. **Tamper Detection**: Altering or deleting a historical row causes automated chain verification to fail with the exact corrupted row index.
3. **Authenticated Access**: Unauthenticated access to `GET /findings` is denied with `403 Forbidden`.
4. **Automated Verification**: Complete test suite passes: `make test-telemetry`.

---

## 6. Verification & Validation Strategy

```bash
# Verify telemetry queue operations and finding retrieval
make test-telemetry
```
