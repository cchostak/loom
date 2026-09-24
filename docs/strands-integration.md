# Strands integration design

Strands chooses actions; Loom authorizes them. The runtime is an optional client
of the existing authenticated control plane, which forwards to Agentgateway.
No Strands classes or events enter the Go policy model.

## Implementation plan and inspected boundaries

The existing boundary supports bounded non-streaming text completions and a
read-only MCP subset. A custom Strands Model translates a strict JSON action
protocol into native Strands stream events; it never invokes tools itself.
Strands MCPClient uses an HTTP transport to the same authenticated boundary.
Unsupported model formats, approvals, transformations and MCP methods fail closed.

Four roles run in separate one-shot containers. A host-side workflow runner
passes bounded JSON handoffs over stdin/stdout, never mounting workspace files.
Each container receives only its own opaque credential; the registry supplies
principal, workload and session. Agent names and client metadata grant nothing.
Researcher can read, operator can list, planner and publisher have no file tools.
All may request the one configured model. External publishing stays unavailable.

An internal agents network connects only these clients and the control plane.
There are no host ports, provider credentials, Docker socket, arbitrary bind
mounts, shell tools or runtime package installation. DNS forwarding is disabled;
service discovery remains available. Credential secrets are the only host files
projected into a runtime. Host orchestration is trusted developer tooling, not an
agent capability. A compromised process can use its own credential but cannot
obtain another role's credential. Local hooks are never relied on for isolation.

Provenance mirrors security.DataContext. Tool/model/peer output stays tainted and
untrusted across handoffs; parents preserve lineage. This is descriptive client
metadata, not an authenticated provenance attestation. Loom independently treats
all ingress as untrusted and never elevates permissions on delegation.

Local hooks bound turns, tools, elapsed time and emit content-free lifecycle
records. HTTP adapters correlate returned Loom decision/trace IDs with role and
workflow IDs. Core audit remains authoritative and distinguishes authorization
from execution. No raw prompts, tool arguments or outputs enter telemetry.

Keyless CI runs the real Strands loop with a fixture provider behind actual
Agentgateway, retaining production control-plane policy, MCP and guardrails.
The fixture is test-only and cannot be reached from the agent network. Tests
exercise denials, traversal, tainted handoffs, inert exfiltration, runaway loops,
failure paths and network bypass attempts. The old docker/swarm simulation stays.

## Residual boundaries to review

Python and its dependencies can perform local computation and access their own
container files; filesystem isolation, credentials and networks constrain a
compromised interpreter, not tool registration. Containers share the host kernel;
a kernel/runtime escape is outside this Compose boundary (use gVisor/VMs).
Allowed model invocation is an intentional export path: unknown confidential
text may pass content inspection. Do not grant model access to workloads that
must never export any data. No general DLP guarantee is claimed. Client lineage
cannot establish trusted provenance against a compromised process; future signed,
server-maintained lineage and destination-aware export policy are required.
