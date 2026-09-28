# TASK-RV-03: Cryptographic Data Lineage & Ancestor Access Re-verification

## Epic: 04-rag-vector-governance
**Status**: Ready for Implementation  
**Security Classification**: High (Access Control & Compliance)  
**Relevant Standards**: NIST SP 800-53 (AC-3 Access Enforcement), ISO 27001 (A.8.2 Information Classification)  

---

## 1. Context & Tooling Evaluation

In enterprise organizations, user roles and document classification levels change dynamically (e.g. employee department transfers, project declassifications, vendor contract terminations). If vector embeddings store static permissions stamped during ingestion, revoking a user's access to the source document does not prevent them from retrieving the document's vector chunks.

### Tooling Trade-Off Matrix

| Re-Authorization Architecture | Enterprise Fit | Pros | Cons / Constraints | Selection Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| **Real-Time Synchronous ACL Check on Read** | High (Zero Stale Window) | Instant permission revocation; source ACL store remains single source of truth; zero stale authorization. | Adds a fast permission cache lookup (~2-5ms) to the RAG query pipeline. | **Selected Baseline Standard**: Cache live ACLs in Redis/Valkey and re-verify before prompt assembly. |
| **Batch Vector Re-indexing on ACL Change** | Low (Resource Intensive) | Keeps vector metadata updated eventually. | Massive GPU/compute re-embedding costs; multi-hour stale permission exposure windows. | **Anti-Pattern**: Do not rely on batch re-indexing for authorization changes. |
| **Cryptographic Provenance (OpenLineage)** | High (Audit & Non-Repudiation) | Tracks exact transformation lineage from raw bronze filings to gold semantic chunks; SHA-256 chunk citations. | Requires metadata catalog storage; increases telemetry payload size. | **Mandatory Compliance Standard**: Enforce cryptographic chunk citation digests in all audit logs. |

---

## 2. Problem Statement & Threat Vectors

When a user's access to a sensitive document (e.g. quarterly executive board notes) is revoked, they should immediately lose the ability to query that document's contents. In naive RAG architectures, the vector database maintains its own cached permissions, leaving unauthorized chunks accessible indefinitely.

### Threat Vectors
- **Stale ACL Authorization (CWE-285)**: Querying vector embeddings of documents to which user access was recently revoked.
- **Privilege Escalation via Derived Summaries (CWE-269)**: Using an unprivileged summary to bypass source document classification.
- **Untraceable Model Citations**: LLMs answering with sensitive data without provenance tracing back to source records.

---

## 3. Architecture & Technical Blueprint

```text
User Query ("Retrieve executive compensation notes")
        │
        ▼ 1. Vector Search Pre-Filter
Matched Vector Chunks (DocID: "doc-999", Chunk: 4)
        │
        ▼ 2. Synchronous Ancestor Re-Authorization Check
Access Control Service (Live Source ACL Store / Redis Cache)
        │
        ├── 3. Fetch current live ACL for "doc-999"
        │      ├── User ID: "user-456"
        │      └── Current Allowed Groups: ["exec-hr"]
        │
        ├── 4. Evaluate: User "user-456" in ["exec-hr"]?
        │      ├── NO: Drop chunk from context; log authorization revocation event
        │      └── YES: Admitted into context
        │
        ▼ 5. Prompt Assembler (Boundary)
Context Injected into Prompt with Cryptographic Citation Digest:
SHA-256(doc-999 || chunk-4 || source-revision)
        │
        ▼ 6. Audit Telemetry
Audit Logger records exact document citation digests in telemetry
```

---

## 4. Implementation Tasks

- [ ] Implement synchronous ancestor ACL re-check hook prior to assembling RAG prompt context.
- [ ] Connect re-check hook to live enterprise directory / permission cache.
- [ ] Implement cryptographic chunk citation hashing (SHA-256) linked to source revisions.
- [ ] Ensure derived summaries maintain signed lineage metadata linking to parent documents.
- [ ] Add automated test suites verifying immediate revocation of vector chunk visibility.

---

## 5. Definition of Done (DoD) & Acceptance Criteria

1. **Instant Revocation**: Revoking a user's permission to a source document immediately prevents that document's chunks from appearing in their RAG completions.
2. **Cryptographic Provenance**: Every retrieved chunk included in audit logs includes the SHA-256 digest of the originating document.
3. **Derived Lineage Integrity**: Summaries and derived data inherit parent classifications and cannot be used to bypass access controls.
4. **Automated Verification**: Complete pipeline test suite passes: `make pipeline-rag`.

---

## 6. Verification & Validation Strategy

```bash
# Verify medallion pipeline lineage and retrieval authorization
make pipeline
make pipeline-rag
```
