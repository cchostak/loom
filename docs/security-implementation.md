# Security hardening: implementation and evidence

Date: 2026-09-23. This is a substantial P0/P1 increment, not a claim that all
production requirements or all attacks in the threat model are solved.

## Original assessment

Agentgateway, synchronous hooks, CEL tool filtering and deterministic tests were
useful foundations. Mandatory identity/resource mediation was missing. Root
containers, a writable workspace in the provider-key holder, dynamic npm tooling,
all-interface port publishing, PII inspection that did not alter forwarded bytes,
and fail-open ingestion created practical exposure. The lab's in-memory grants
were not production authorization. Several architecture claims contradicted
Compose. These findings motivated the changes below.

## Interfaces and enforced invariants

| Interface / implementation | Enforcement and threat addressed |
| --- | --- |
| `IdentityContext`, `Authenticator`, `Registry` | Local opaque bearer credentials resolve to fixed principal, workload, tenant, session and scopes. Registry expiry/audience checked on every request; removal revokes new requests. Inbound identity headers confer no authority and credentials are not forwarded. This is local authentication, not an OAuth implementation. |
| `ActionRequest`, `boundary.Parse` | Strict text-only model and MCP schemas, normalized reserialization, explicit resource/destination/side-effect context. Unknown actions/arguments, traversal, streaming and unsupported recursive/delegation methods deny before dispatch. |
| `DataContext`, `Derived` | Source/producer/origin/trust/sensitivity/taint/integrity/parent representation; transforms preserve taint/classification and clear obsolete integrity. Ingress and MCP results remain untrusted. Persistent RAG lineage is not yet enforced. |
| `Policy`, `PolicyDecision` | Versioned JSON grants match principal/workload/tenant/scope/action/resource/destination/trust/classification/side effects. Default deny; policy errors deny. Decisions have random IDs, rule/version, reason, obligations and expiry. `require_approval` denies dispatch until a future executor supports approval. |
| `safefs.Open`, `Execute`, `Serve` | Linux descriptor-relative opens use `O_NOFOLLOW` at every path component. Only regular text files and bounded directory listings; no write, shell or network tools. This protects actual execution from traversal and symlink replacement, not just path validation. |
| `Detector` and guardrail handlers | Replaceable sensitive-data detector contract; Presidio/known-secret detection and inexpensive string checks. Missing/bad/slow detector results reject. Detected PII is rejected, not falsely described as removed from forwarded content. Encoded JSON strings and extension fields are inspected. |
| `SecurityEvent`, `Audit` | Intent and result events correlate policy and execution with server-generated IDs/W3C trace context. Identity and action digest are retained; bodies, arguments, credentials and raw upstream errors are excluded. File events are synced; failed intent writes prevent dispatch. At 100 MiB the local file stops accepting events/dispatch until operator maintenance. |
| `Budgets`, `Circuit` | Per-credential-session rate, operation count, concurrency, input/output-token bounds and workflow age; 30-second request deadline and bounded responses. Three upstream failures open a model/tool circuit for 30 seconds. No client-supplied session can reset quota. State remains process-local. |
| `Approvals` | Backend-only HMAC contract binds exact serialized action, identity, resource, destination, arguments, effects, decision, policy version and expiry; consumption is one-time within the process. No issuer API, signing key provisioning or privileged executor is enabled. Operator authentication and durable replay prevention remain required. |

Additional invariants: only the boundary publishes AI APIs; IDE and raw gateway
have no shared network; filesystem subprocess starts with an empty environment;
MCP mounts and core root filesystems are read-only; capabilities are dropped;
container CPU/memory/PID/file-descriptor/log sizes are bounded. The IDE retains a
writable home but receives no sudo password. All host ports bind to loopback.

The collector removes span/resource/scope/event attributes, names, status text,
trace state and links before export, and has no raw-log/debug exporter. The
`ottl.set.allowNil` feature gate is needed to clear links in the pinned collector.
Tracing outages do not authorize requests or prevent unrelated safe operations.
Jaeger is not the security audit log.

## Changed surfaces

* `docker/security/`: context, policy, credentials, audit, approval, budget and
  circuit contracts and tests. `config/policy.json`: initial local grants.
* `docker/boundary/`, `docker/cmd/control-plane/`, `docker/Dockerfile.control`:
  authenticated mediation, schema validation, inspection and bounded dispatch.
* `docker/safefs/`, `docker/cmd/filesystem/`, gateway Dockerfile/config:
  small stdio MCP adapter replaces Node/npm; second CEL allowlist retained.
* `docker/main.go`, `handlers.go`, `detectors.go`, `pii/`, `swarm/client.go`:
  split handlers, fail-closed sensitive-data checks, bounded dependency responses
  and malformed-action rejection. The original inexpensive content detector stays.
* Compose, isolation override and collector config: explicit networks, loopback
  publishing, non-root users, mounts, limits and telemetry suppression. Presidio's
  original invalid config path/port were corrected against the pinned image.
* `pipeline/`: guardrail/PII failures no longer promote unchecked documents;
  scoped pipeline credential for model calls; unprivileged runtime/storage.
* `.github/`: SHA-pinned Actions, reduced permissions, dependency/workflow review,
  blocking HIGH/CRITICAL filesystem/image vulnerability scans, OCI SBOM and
  provenance metadata. Core image bases and analyzer/collector/Jaeger are pinned
  by digest; IDE/pipeline dependency modernization remains separate work.
* `scripts/`, tests, Makefile and `.env.example`: generated expiring local
  credentials, safe example, keyless real-runtime regression commands.
* README, SECURITY, ADR 0002, swarm docs, threat model and roadmap: corrected
  claims, migration steps, test distinctions and explicit production gaps.

## Test evidence

| Test layer | Command / evidence | What it proves and does not prove |
| --- | --- | --- |
| Policy/security units | `cd docker && go test -v -race ./... && go vet ./...` | Authority/scope/default deny/revocation, path validation, budgets/circuit, action-bound approvals, audit failure/capacity and taint propagation. Does not prove distributed semantics. |
| HTTP boundary integration | Included in Go tests (`boundary`) | Real HTTP with controlled upstreams: no dispatch on auth/policy/guard failure, strict arguments, limits, timeouts, redirects, circuit opening, credential stripping, unsafe result suppression and audit correlation. No paid provider request. |
| Actual filesystem execution | Included in Go tests (`safefs`, filesystem process tests) | Real descriptor reads, internal/external symlink and FIFO rejection, unknown/write/exec denial, sizes and MCP protocol behavior. |
| Parser/property fuzzing | `go test ./security -run '^$' -fuzz FuzzWorkspacePath -fuzztime=3s -parallel=2`; similarly `./safefs -fuzz FuzzMCPParser` | Exercises parser/path invariants; finite fuzzing is not a proof of all inputs. |
| Static/Python regressions | `python -m unittest discover -s tests -p 'test_*.py'` | Compose/CI exposure and privilege invariants; bootstrap permissions; malformed/unavailable guard/PII dependency handling. Python tests use mocked HTTP, not a fully built embedding pipeline. |
| Real gateway regression | `python3 tests/gateway_security.py` | Authenticated boundary → actual Agentgateway → stdio MCP discovery and file read; denies unknown credentials, arguments, tools, writes, commands, path/symlink escapes and spoofed sessions. |
| Real telemetry regression | `python3 tests/telemetry_security.py` | Injects inert secret markers into known OTLP fields; actual collector/Jaeger export retains trace ID but not those markers. Does not protect a compromised collector/host or prevent arbitrary covert channels. |
| Live container isolation | `python3 tests/container_security.py` | Running containers have intended users, caps, limits, publishing and read-only mounts; Node/npm absent. This is not a kernel escape test. |
| Swarm simulation | `make lab` | Live webhook detection with simulated grants/handoffs. The score is explicitly not proof of runtime delegation enforcement. |

The three live test scripts are combined by `./tests/smoke_test.sh`. They use inert
fixtures, remove their own workspace files, and do not call a paid model.
Unit coverage measured during validation: boundary 89%, security 94%,
filesystem adapter 89%, PII 84%. Startup mains/older code lower the overall total;
these package figures should not be interpreted as repository-wide coverage.

## Threat mapping

| Reference threat | Implemented mitigation | Remaining limit |
| --- | --- | --- |
| OWASP Agentic ASI01 goal hijack; LLM prompt injection | Untrusted input classification, decoded-content checks, capability enforcement independent of prompt obedience | Obfuscated/novel instructions and classifier false negatives remain possible |
| ASI02 tool misuse; LLM excessive agency | Resource/argument checks, bounded read-only tools, no write/exec capability | Adding tools requires new adapters and policy tests |
| ASI03 identity/privilege abuse | Trusted credential registry, fixed workload/session, no header authority or credential forwarding | Production OAuth/OIDC and workload attestation absent |
| ASI04 supply-chain risk; LLM supply chain | Immutable action/base pins, enforced scans, SBOM/provenance generation, no runtime npm | No signed release-admission verifier or claimed SLSA level |
| ASI05 unexpected code execution | No command tools, no Node/npm, non-root/read-only mounts, reduced capabilities | Compromised gateway/IDE and host remain serious boundaries |
| ASI06 memory/context poisoning; LLM data poisoning | Taint type/transform tests, ingestion failure closes | Durable RAG/inter-agent provenance and memory policy incomplete |
| ASI07 insecure inter-agent communication | Delegation is not granted; incoming identities have no authority | Authenticated delegated authority protocol is not implemented |
| ASI08 cascading failures; LLM unbounded consumption | Deadlines, quotas, bounded input/output, circuits, security failure defaults | No durable spend accounting/distributed budgets or immediate cancellation |
| ASI09 human-agent trust exploitation | Exact-action approval contract, no permissive execution path | No operator step-up flow or approval UI/API |
| ASI10 rogue agents; LLM sensitive information disclosure | New-dispatch revocation/emergency deny, inspection, restricted tools and telemetry | A compromised gateway can still use its provider key and Internet egress |

ACS, NIST AI RMF and SLSA are reference models for the boundary/lifecycle design;
no certification or complete standard-control coverage is asserted. Current
primary references are linked in [the roadmap](security-roadmap.md).

## Remaining P0/P1 and second-pass review

A malicious user/model cannot grant a new tool merely by changing prompt text.
A malicious workspace can still supply persuasive content, but cannot make the
filesystem adapter follow a symlink outside its descriptor root. A malicious MCP
result is bounded and inspected before release; that is not reliable semantic
classification. The raw gateway remains reachable to trusted mediation-network
containers, so compromising one of those containers can bypass ingress identity.
The gateway still holds the provider key and has Internet egress. A compromised
IDE can read its workspace and communicate outside Loom. Host compromise defeats
local credentials, policy and audit storage.

Production blockers remain: current OAuth/OIDC/TLS deployment, network-enforced
egress/provider credential separation, isolated management/service identities,
durable quotas/revocation/approval consumption, authenticated append-only remote
audit, and persistent tenant/provenance-aware ingestion. Detailed interfaces and
acceptance criteria are in the [roadmap](security-roadmap.md). Unsupported actions
stay denied; none of these gaps is masked by a lab score.

## Migration and operation

Run `make init`, configure `.env`, then `make up`. Existing clients must set the
new generated bearer credential and use the control-plane endpoints; old raw
Agentgateway/guardrail/OTLP ports are no longer published. Only two filesystem
tools remain, and streaming/multimodal/function-calling/provider extensions are
not supported. Configure a narrow explicit model grant for additional models.

Keep credentials out of the workspace. Registry/policy edits apply to new
requests; revocation/emergency deny does not cancel in-flight actions. Restarting
resets local budgets/circuits/session bindings; reconnect MCP clients. Policy
changes should be reviewed, versioned, tested and atomically replaced in the
mounted directory. Archive/rotate local audit storage with the control plane
stopped; do not delete forensic records to recover from capacity exhaustion.

For local tests install `httpx==0.27.2` in a virtual environment as shown in README.
Full image scans need Trivy/network access; runtime tests need Docker and the
running stack. The optional embedding pipeline is not covered by core smoke tests.

## Final validation results

* Go race tests and vet passed; Python regression suite passed (14 test methods,
  including table-driven dependency failure cases).
* Three-second fuzz runs completed 103,132 path inputs and 19,751 MCP parser
  inputs without a failure. These are bounded local runs, not exhaustive proofs.
* All three real Compose smoke scripts passed after rebuilding: actual gateway
  authorization/read confinement, trace correlation through Jaeger, secret-marker
  suppression and live container isolation. The local IDE also starts successfully.
* The rebuilt swarm lab passed all four deterministic scenarios; two of its
  controls remain simulations as described above.
* Trivy 0.74.0 filesystem dependency/secret scan passed, excluding `.env`, `.loom`
  and `.git` runtime/private state. HIGH/CRITICAL scans of the rebuilt
  `loom-control-plane`, `loom-guardrail-proxy` and `loom-agentgateway` images each
  reported zero findings with the downloaded database. This does not cover every
  third-party/optional pipeline image or guarantee future scan results.
* The first image scans found vulnerable Go 1.26.1 standard-library code and
  unnecessary Debian packages. All Go builds now use digest-pinned Go 1.26.8;
  gateway uses the pinned minimal upstream image with a static health/filesystem
  helper and no shell/Node/npm. This closed those image findings without scanner
  exceptions or disabling the gate.
* Agentgateway configuration validation, actual collector startup/privacy export,
  Compose validation, ShellCheck, YAML lint and Zizmor's default workflow audit
  passed. GitHub-hosted CI and OCI SBOM/provenance artifact generation are
  configured but were not executed on GitHub during this task.

Reproduce the scans with Trivy 0.74.0 (use a writable private cache):

```bash
trivy fs --cache-dir /tmp/loom-trivy-cache --scanners vuln,secret \
  --severity HIGH,CRITICAL --exit-code 1 \
  --skip-dirs .loom --skip-dirs .git --skip-files .env .
for image in loom-control-plane loom-guardrail-proxy loom-agentgateway; do
  trivy image --cache-dir /tmp/loom-trivy-cache --scanners vuln \
    --severity HIGH,CRITICAL --exit-code 1 "$image"
done
```

Go patch versions were checked against the
[official release history](https://go.dev/doc/devel/release).
