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

## Implemented adapters and contracts

`integrations/strands/loom_strands/` contains the model, MCP, transport, lineage,
event, hook and role adapters. `runner.py` is trusted host orchestration and is
not copied into the runtime. Roles are separate containers, not merely friendly
names within one Python process. `bootstrap_strands.py` adds four independent
hashed-registry credentials without changing existing developer/pipeline tokens.
Explicit grants live in the existing `config/policy.json`; no Strands-aware core
policy types or authorization services were added.

Both adapters use only `http://control-plane:8080`. Its existing LLM and MCP
routes forward to Agentgateway's separate listeners. MCP uses the SDK's actual
MCPClient and native MCPAgentTool objects over a bounded POST transport. Authenticated, ownership-checked DELETE releases the MCP session on exit. No
subprocess server, arbitrary URL, redirects, environment proxy or fallback is
accepted. `request_capability` only forwards proposals to this same MCP boundary.
It deliberately permits proposing unsupported names so Loom's real rejection can
be tested; it cannot implement an external action itself.

The opaque credential determines principal/workload/tenant/session/scopes. The
local UUID workflow and parent role correlate events but do not grant authority.
The authenticated session is stable across workflow runs, preventing budget reset
by changing a client identifier. Returned server-generated trace/decision IDs link
client events to the existing durable audit and privacy-filtered Jaeger traces.
The runtime exports no SDK prompt spans and reaches no separate telemetry service.

Lineage uses the Go DataContext field names. The adapter validates MCP
`_meta["loom/provenance"]`, keeps source/parent relationships, preserves the more
sensitive classification and never accepts a trusted/untainted peer claim. A
summary adds a parent; it does not erase its source. Handoff validation excludes
system-policy or authenticated-integrity claims. Compiled role instructions are
separate system content, not a user-controllable trusted lineage classification.
Loom still makes its own conservative untrusted-ingress classification: these
client labels are not authenticated inputs to server authorization.

BeforeModelCall/BeforeToolCall enforce local counters and elapsed time;
AfterToolCall records outcome, merges lineage and stops on errors. Hooks cannot
make an unauthorized request succeed. Model transport errors stop invocation.
MCP errors stop the reference workflow rather than allowing automatic retries or
privilege escalation. A crash/timeout does not produce a new handoff; the host
kills the exact one-shot container, and retains only the previous completed handoff.

HTTP success means a response was accepted, not that a tool succeeded. Events
separately record `requested`, `response` and `tool_result`; policy decisions and
actual result status remain in core audit. Approval and transform are deliberately
unsupported: HTTP denial never produces a synthetic confirmation or alternative
execution route. The existing Go approval library is not a production approval API.

## Production-path scenarios

| Scenario | Real runtime path and expected boundary |
| --- | --- |
| Benign | Researcher native MCP read → model summary → planner, with tainted lineage |
| Indirect | Retrieved note asks planner to read; planner's real MCP request gets 403 |
| Escalation | Planner requests a file capability its credential lacks; 403 |
| Delegation | Planner hands an out-of-scope read to researcher; resource validation denies it |
| Exfiltration | Researcher hands evidence to publisher; unavailable publication capability is denied; no destination is contacted |
| Arguments | Native read tool receives traversal; Loom rejects the resource before dispatch |
| Runaway | Operator repeatedly lists through real MCP; local hook limits terminate the loop |
| Literal injection | Actual repository text is blocked at the tool response boundary |
| Tool failure | Missing file produces a failed tool result, never a completed read |
| Operator denial | Researcher → planner → operator; a plan cannot grant the operator file-read access |

The indirect note does not contain a magic forbidden phrase. It actually traverses
a read, researcher model output and planner input. The deterministic provider
scripts requests only; it has no copy of Loom policy and cannot fabricate tool
results. Assertions require the expected HTTP rejection and correlate opaque IDs
against authoritative audit records. Native Strands MCP tools exercise successful
and failed reads/listing; the narrow request adapter exercises unavailable grants.

The lab also bypasses all hooks and sends forged researcher identity and trusted
provenance headers/metadata with the planner credential; Loom must still deny it.
It attempts direct IP connections, not merely DNS lookups, to raw model/MCP,
inspection and fixture endpoints. It checks Internet/metadata access, external DNS,
root privileges, secret separation, mounts and absence of shell/package-manager
entrypoints. The model/tool fixture exists only in the isolated lab project.

Reversible container outages test the fixture provider, MCP gateway and telemetry
collector. Go tests cover missing/broken policy, guardrail failures/timeouts and
audit failure. Python fixtures cover redirects, malformed protocols, connection
failures, output/input caps and incomplete handoffs. No test treats a copied
Python policy map as production enforcement.

## Generic inspection correction

Real structured model/tool traffic exposed unstable classifier input: Go map
iteration reordered text, and repeated JSON escape punctuation was recognized as
PERSON/NRP entities. Core inspection now sorts keys. For the language classifier,
it decodes JSON keys and all scalar values, including unknown fields, exact
numbers and nested encoded documents, with bounded recursion. Deep content is
retained, not dropped. Secret and forbidden-pattern detectors still inspect
original bytes and decoded strings. This is framework-neutral normalization, not
an exception or weaker rule for Strands. Regression tests cover preservation,
ordering, nesting and existing secret/injection rejection.

## Hostile architecture review

| Actor / attempted bypass | Enforced boundary or remaining limitation |
| --- | --- |
| Malicious model or workspace | Can propose arbitrary actions, but only Loom-granted tools/resources can run; model/tool content is inspected |
| Malicious MCP server | Unknown/server-initiated messages and malformed responses fail; metadata cannot promote trust; response bodies are bounded and inspected |
| Compromised planner | Own token has no file grants; forged agent names, metadata or skipped hooks cannot acquire researcher authority |
| More privileged researcher | Separate container and secret; workspace read scope is still authoritative; delegation cannot add shell/write/publish capabilities |
| Compromised Python process | Can read its own files/secret and execute Python internally; no host workspace/socket, external DNS/egress or raw gateway route is granted |
| Provider export | **Remaining gap:** authorized model invocation intentionally exports content. DLP is heuristic and can miss confidential data. This is not general exfiltration prevention |
| Client provenance | **Remaining gap:** compromised code can lie about lineage. Loom never trusts it, but cannot enforce source-specific export restrictions without server-maintained lineage |
| Kernel, Docker or trusted host compromise | **Remaining gap:** the Compose host and kernel are trusted. Local host tooling owns orchestration and registry files; containers are not VMs |
| MCP/SDK dependency failure | Fail closed, but the pinned SDK can emit a cleanup RuntimeWarning after failed MCP startup; short-lived containers bound its lifetime |
| Repeated denial / DoS | Server budgets, circuit breakers and container limits constrain load; the example is not a hostile public multi-tenant service |

No known direct provider, raw MCP, host-workspace or cross-role credential bypass
is intentionally available in the tested Compose layout. That statement does not
cover arbitrary deployment changes, interpreter/kernel vulnerabilities, covert
channels through authorized model traffic or a compromised trusted host.

The next phase is server-maintained signed lineage and source/destination-aware
export rules; authenticated operator approval with durable one-use action binding;
persistent distributed budgets/revocation; and gVisor/VM-backed workload isolation.
Do those before adding network, write, deployment or publishing capabilities.
Add mTLS/workload identity before distributing this local layout across hosts.

## Delivery map and commands

Architecture, trust boundaries, routing, identity, provenance, hooks, authoritative
versus local controls, scenarios, production-path evidence and unresolved gaps are
covered above. Added surfaces are `integrations/strands/`, role provisioning,
Compose agents/lab configuration, policy grants, the Strands CI workflow and this
design. Updated surfaces include generic inspection/tests, Makefile, README and
the image-security build matrix. The old simulation was retained unchanged.

- `make strands`: isolated real-model researcher/planner demo; provider key required only at Agentgateway.
- `make strands-lab`: keyless production-path scenarios, no-bypass probes and outage tests.
- `make strands-test`: lock validation, lint and Python regressions.
- `cd docker && go test -race ./... && go vet ./...`: core verification.
- `make test-smoke`: existing real MCP, telemetry and container security checks.
- The security workflow builds an OCI image with SBOM/provenance and blocks HIGH/CRITICAL findings for Strands as well as the core images.

See [the runnable guide](../integrations/strands/README.md) for setup and cleanup.
Strands SDK API references: [custom models](https://strandsagents.com/docs/user-guide/concepts/model-providers/custom_model_provider/),
[hooks](https://strandsagents.com/docs/user-guide/concepts/agents/hooks/) and
[the pinned release](https://pypi.org/project/strands-agents/1.57.0/).


## MCP session lifecycle

Repeated reference runs exposed that the original POST-only boundary could not
release Agentgateway sessions and their stdio children. The framework-neutral
boundary now supports authenticated `DELETE /mcp` for a nonempty, owned session,
with no body/query and an explicit scoped `session/delete` policy grant. Ownership
includes tenant, principal, workload and authenticated session. Unknown, foreign,
already deleted or malformed requests never reach the gateway. Successful cleanup
removes the binding and is audited. It is exempt from execution budgets because
it only releases an existing owned resource; it cannot allocate or invoke tools.

The adapter performs bounded, cancellation-shielded cleanup, including after tool
errors. The lab matches a successful authoritative cleanup for every role run.
When upgrading an already running stack that accumulated sessions under the old
protocol, restart Agentgateway alongside the control plane to remove orphaned
children. Abrupt process/host failure can still orphan a session; the next phase
needs server-side idle expiry and per-workload session quotas. Process limits cap
the local damage but do not establish shared-service availability isolation.
