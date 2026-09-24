Your task is to add **Strands Agents as a first-class reference agent runtime on top of Loom**.

The architectural rule is:

> Strands decides what an agent wants to do. Loom decides whether it is permitted to do it.

Do not make Strands part of Loom's trusted security boundary.

Do not redesign Loom around Strands.

Do not allow Strands to bypass Loom for privileged model calls, tool calls, filesystem access, network activity, or other consequential actions.

The intended architecture is:

```text
              Agent/Application Layer

                 Strands Agents
                       │
             ┌─────────┴─────────┐
             │                   │
         Model calls          Tool calls
             │                   │
             ▼                   ▼

              Loom Enforcement Plane

          Agentgateway LLM    Agentgateway MCP
              :8080               :3000
                 │                   │
         request/response        authorization
           guardrails             + policy
                 │                   │
                 └─────────┬─────────┘
                           │
                 identity / provenance
                 audit / security events
                 budgets / approvals
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
        model provider               MCP tools
```

## Primary objective

Introduce a real Strands-based agent runtime so Loom can demonstrate and test security against actual autonomous and multi-agent execution instead of only simulated agent behavior.

The Strands integration should become:

1. a reference secured agent runtime,
2. an integration test target,
3. an adversarial multi-agent security harness,
4. an example showing how third-party agent frameworks should integrate with Loom.

Loom must remain framework-neutral.

A future LangGraph, custom agent runtime, or other framework must be able to use the same Loom APIs and security semantics.

## Inspect before changing

Before implementing anything:

* inspect the full repository,
* inspect the current Agentgateway configuration,
* inspect the current guardrail implementation,
* inspect MCP authorization,
* inspect Docker Compose,
* inspect `docker/swarm/`,
* inspect existing security/evaluation tests,
* inspect OpenTelemetry configuration,
* inspect any identity/policy/security interfaces introduced by previous work,
* identify all possible ways a Strands process could bypass Loom.

Document the integration design before coding in:

`docs/strands-integration.md`

Keep the design concise and implementation-oriented.

## Repository structure

Prefer a structure similar to:

```text
integrations/
└── strands/
    ├── README.md
    ├── pyproject.toml
    ├── Dockerfile
    ├── loom_strands/
    │   ├── __init__.py
    │   ├── main.py
    │   ├── config.py
    │   │
    │   ├── agents/
    │   │   ├── researcher.py
    │   │   ├── planner.py
    │   │   ├── operator.py
    │   │   └── publisher.py
    │   │
    │   ├── orchestration/
    │   │   ├── graph.py
    │   │   └── swarm.py
    │   │
    │   ├── loom/
    │   │   ├── model.py
    │   │   ├── mcp.py
    │   │   ├── identity.py
    │   │   ├── policy.py
    │   │   ├── provenance.py
    │   │   └── events.py
    │   │
    │   ├── hooks/
    │   │   ├── security.py
    │   │   ├── provenance.py
    │   │   ├── audit.py
    │   │   └── limits.py
    │   │
    │   └── scenarios/
    │       ├── benign.py
    │       └── adversarial.py
    │
    └── tests/
```

Adapt this if the existing repository suggests a cleaner convention.

Do not place the production/reference Strands runtime inside the current `docker/swarm/` package.

The existing `docker/swarm/` code is an evaluation/simulation harness and should remain conceptually separate until individual scenarios are migrated.

## Dependency discipline

Use a current stable Strands Agents release.

Pin Python dependencies reproducibly.

Avoid runtime `pip install`, dynamic dependency acquisition, or unpinned arbitrary package loading.

Generate a lockfile using an appropriate Python packaging workflow.

Keep the runtime container minimal.

Do not include unnecessary shells, compilers, package managers, or development dependencies in the final runtime image.

## Core security invariant: no privileged bypass

A Strands agent must not receive privileged direct Python tools such as:

* arbitrary shell execution,
* unrestricted filesystem operations,
* unrestricted HTTP clients,
* direct cloud SDK credentials,
* deployment APIs,
* Git push capabilities,
* arbitrary subprocess execution,

unless they are deliberately implemented as Loom-mediated capabilities.

Do not create a design like:

```python
Agent(
    tools=[
        shell,
        filesystem,
        unrestricted_http,
    ]
)
```

for the secured reference runtime.

Instead:

```text
Strands
   │
   ▼
Loom MCP Gateway
   │
   ▼
authorized capability
```

Privileged tools must cross an authoritative Loom enforcement boundary.

Local Strands tools are acceptable only when they are:

* pure computation,
* deterministic transformation,
* formatting,
* local validation,
* or otherwise incapable of producing meaningful external side effects.

Document which local tools are allowed and why they do not create a bypass.

## Model routing

All secured Strands model calls must route through Loom's LLM gateway.

Do not call OpenAI, Anthropic, Bedrock, OpenRouter, or another provider directly from the secured reference agent.

Configure or implement the appropriate Strands model/provider adapter so the data path is:

```text
Strands
   ↓
Loom Agentgateway :8080
   ↓
request security
   ↓
provider
   ↓
response security
   ↓
Strands
```

Preserve:

* identity context,
* session/workflow correlation,
* agent identity,
* provenance metadata,
* trace correlation,

as far as the existing gateway/API supports.

If Agentgateway's OpenAI-compatible interface cannot carry required trusted metadata directly, implement a safe integration boundary rather than spoofable arbitrary client headers.

Document any current protocol limitation.

## MCP integration

Use Strands' MCP support to connect to Loom's MCP gateway.

The intended path is:

```text
Strands Agent
      │
      │ MCP
      ▼
Loom Agentgateway :3000
      │
      │ authn/authz
      │ capability policy
      │ resource checks
      │ auditing
      ▼
MCP server
```

Do not connect the secured reference agent directly to the filesystem MCP server.

Do not allow Strands to spawn an equivalent filesystem MCP server independently.

The Loom MCP gateway must remain the control point.

Test that attempting to use a tool outside the Loom allowlist fails through the real runtime path.

## Agent identity

Every Strands agent must have a stable logical identity.

At minimum support:

* agent ID,
* agent role,
* workflow/session ID,
* parent/delegating agent where applicable,
* user/principal context where available.

Examples:

```text
researcher
planner
operator
publisher
```

Agent identity must be propagated into Loom security context where possible.

Do not infer authorization solely from friendly agent names.

Agent names are metadata.

Authorization must ultimately derive from authenticated/trusted Loom security context.

## Provenance

Implement provenance propagation through Strands workflows.

Represent distinctions such as:

* user-supplied content,
* trusted system policy,
* retrieved external content,
* repository/file content,
* MCP tool output,
* model-generated content,
* another agent's output.

When an agent hands content to another agent, preserve its provenance and trust classification.

Do not automatically convert:

```text
untrusted external content
```

into:

```text
trusted agent content
```

merely because another model summarized it.

A useful invariant is:

```text
untrusted input
   ↓
researcher
   ↓
summary
   ↓
planner
```

must still carry a relationship to its original untrusted source.

Integrate this with any existing Loom `DataContext` or equivalent abstraction rather than creating a parallel incompatible security system.

## Strands hooks

Use Strands lifecycle hooks where helpful for:

* initializing Loom context,
* assigning agent identity,
* recording agent transitions,
* propagating provenance,
* adding trace/security correlation,
* recording attempted tool use,
* applying local preflight checks,
* enforcing local budget constraints.

However:

> Strands hooks are defense-in-depth, not the authoritative security boundary.

A malicious or compromised Strands process must not be able to gain privileged access merely by skipping a hook.

Anything consequential must still be enforced downstream by Loom.

## Interventions / approvals

Where the current Strands version exposes intervention concepts for:

* allow/proceed,
* deny,
* confirmation,
* transformation,
* guidance,

integrate them cleanly with Loom policy outcomes where appropriate.

Conceptually:

```text
Loom ALLOW
    ↓
Strands proceeds

Loom DENY
    ↓
Strands stops the action

Loom REQUIRE_APPROVAL
    ↓
Strands pauses / surfaces confirmation

Loom REDACT or TRANSFORM
    ↓
Strands consumes the authorized transformed result
```

Do not let Strands make the authoritative privilege decision.

If Loom does not yet expose `REQUIRE_APPROVAL` or transformation decisions in production, create a clean adapter boundary and document the unsupported state rather than pretending the feature is enforced.

## Initial reference agents

Implement a small but meaningful secured multi-agent system.

Use agents approximately like:

### Researcher

Purpose:

* inspect allowed workspace information,
* retrieve/read permitted resources,
* gather context.

Expected privileges:

* read-only.

### Planner

Purpose:

* reason over information,
* produce plans,
* coordinate tasks.

Expected privileges:

* ideally no direct privileged tools.

### Operator

Purpose:

* request actions.

Expected privileges:

* narrow capabilities,
* never automatically receive broad shell/system access.

### Publisher

Purpose:

* represent actions that cross an external trust boundary.

Initially keep actual external publishing inert or mocked unless Loom has a properly enforced destination-aware capability.

Publisher is useful specifically to demonstrate exfiltration and approval controls.

## Build a real adversarial swarm

Implement a Strands-backed version of the existing Loom adversarial swarm concepts.

Include at minimum:

### 1. Indirect prompt injection

Flow:

```text
malicious external/repository content
       ↓
researcher
       ↓
planner
```

Attempt to make downstream agents follow instructions originating from untrusted content.

Expected result:
Loom security policy detects or constrains the attack according to the implemented security model.

Do not rely exclusively on a literal phrase such as "ignore previous instructions."

Include at least one variant that tests provenance/trust boundaries independent of string matching.

### 2. Capability escalation

An agent without a privileged capability attempts to use an unauthorized tool.

Expected result:
The real Loom MCP authorization path rejects the request.

Do not simulate this with an in-memory map.

### 3. Delegation laundering

An untrusted context is passed from a low-privilege agent to a more privileged agent.

Expected result:
Provenance survives the handoff and the downstream privilege boundary cannot be crossed merely through delegation.

### 4. Cross-agent exfiltration

A compromised/untrusted agent attempts to cause another agent to send sensitive information outside the trusted environment.

Expected result:
Loom denies either the data movement, destination, privileged action, or equivalent security boundary.

Keep external exfiltration inert.

### 5. Tool argument attack

Use an allowed tool but malicious arguments.

Examples:

* path traversal,
* unauthorized filesystem target,
* unexpected destination,
* malformed structured parameters.

Expected result:
Loom evaluates arguments/resource context, not merely the tool name.

If current Loom production policy cannot enforce this yet, the test should expose that gap clearly and remain marked as expected-failure only with documented rationale.

Do not hide the deficiency.

### 6. Agent loop / runaway behavior

Create an intentionally pathological agent or swarm path that would repeatedly hand off or call tools.

Expected result:
configured iteration/delegation/tool-call/time/token limits terminate it safely.

## Real enforcement versus simulation

This requirement is critical.

The new Strands adversarial tests must call the real Loom enforcement paths wherever practical.

For example:

BAD:

```text
Strands scenario
    ↓
Python dictionary says tool is denied
    ↓
test passes
```

GOOD:

```text
Strands scenario
    ↓
actual MCP call
    ↓
actual Agentgateway
    ↓
actual Loom policy
    ↓
denied
    ↓
test passes
```

Similarly, do not copy production policy into the test suite and then test the copy.

Tests should exercise real deployed configuration whenever technically reasonable.

## Docker Compose integration

Add an optional Strands service/profile to Docker Compose.

Prefer something like:

```bash
docker compose --profile agents up
```

or an equivalent clearly named profile.

The default Loom quickstart should remain lightweight.

The Strands runtime should connect only to the services it genuinely requires.

Harden the container:

* non-root user,
* `no-new-privileges`,
* dropped capabilities,
* resource limits where practical,
* narrow volumes,
* no Docker socket,
* no host filesystem mounts,
* read-only root filesystem where compatible,
* tmpfs for required writable temp state,
* minimal runtime dependencies.

Do not expose a Strands service port to the host unless the integration genuinely needs one.

## Networking

Ensure the secured Strands runtime:

* can reach Loom Agentgateway,
* can reach required Loom telemetry endpoints only if needed,
* cannot directly reach internal MCP implementation containers if that would bypass Loom,
* cannot access unnecessary internal services,
* cannot gain privileged Docker/host access.

If Docker Compose's single `ide-net` network currently prevents enforcing these boundaries cleanly, introduce sensible network segmentation without making local development excessively complicated.

## Observability

Instrument Strands so one distributed execution can be correlated across:

```text
Strands workflow
   ↓
agent
   ↓
model request
   ↓
Loom gateway
   ↓
tool request
   ↓
policy decision
   ↓
tool execution
```

Prefer OpenTelemetry-compatible instrumentation.

Reuse existing Loom telemetry infrastructure.

Do not create a completely separate observability stack.

Include attributes such as:

* workflow/session ID,
* agent ID,
* parent agent,
* tool name,
* decision ID,
* policy outcome,
* provenance classification,

where safe.

Never export secrets, credentials, full authorization headers, or sensitive raw values merely for observability.

## Security events

Where Loom has a structured `SecurityEvent` or equivalent system, emit/correlate relevant Strands lifecycle activity with it.

At minimum make it possible to distinguish:

```text
agent requested action
policy denied action
```

from:

```text
agent requested action
policy allowed action
action completed
```

Avoid claiming that an action executed merely because policy allowed it.

Authorization and outcome are distinct events.

## Budgets and execution limits

Configure explicit bounded execution for the Strands reference runtime.

At minimum consider:

* model turns,
* tool calls,
* agent handoffs,
* recursion/depth,
* elapsed workflow time,
* request size,
* output size,
* token limits if available.

Use Strands-native limits where appropriate and Loom-global limits where security requires authority outside the agent process.

Document which limits are:

```text
local safety controls
```

versus:

```text
authoritative Loom controls
```

## Failure semantics

Test what happens when:

* Loom LLM gateway is unavailable,
* Loom MCP gateway is unavailable,
* policy service returns deny,
* policy service fails,
* guardrail times out,
* tool invocation fails,
* telemetry fails,
* an agent crashes halfway through a handoff.

Security-critical failures must not silently fall back to direct provider/tool access.

There must be no behavior like:

```text
Loom unavailable
      ↓
connect directly to model/provider/tool
```

Fail safely instead.

## Developer ergonomics

Add developer commands such as:

```bash
make strands
make strands-test
make strands-lab
```

or names consistent with the current Makefile.

A developer should be able to:

1. initialize Loom,
2. start the required services,
3. run a benign Strands example,
4. run the adversarial Strands lab,
5. inspect results and traces.

Keep the setup reproducible.

Document required API keys clearly.

Where possible, keep security regression scenarios keyless/deterministic.

Separate:

```text
real-model demonstration
```

from:

```text
deterministic security CI
```

so CI does not depend on external LLM availability or paid API usage.

## CI

Add CI coverage for the Strands integration.

At minimum:

* dependency installation/lock validation,
* Python lint/static checks,
* unit tests,
* container build,
* integration startup,
* MCP authorization test through the real gateway,
* adversarial deterministic scenarios,
* no-bypass tests,
* provenance handoff tests,
* security-event correlation tests where feasible.

Avoid requiring external provider API keys for mandatory pull-request CI.

Create optional/manual real-model evals separately if useful.

## No-bypass tests

Explicitly test architectural bypass conditions.

Examples:

* Strands container cannot access host Docker socket.
* Strands container does not mount arbitrary host filesystem paths.
* secured agent configuration does not contain direct model provider credentials.
* secured agent configuration points models through Loom.
* secured MCP configuration points through Loom.
* unauthorized direct MCP endpoint access is unavailable where network architecture supports this.
* local privileged shell/filesystem tools are absent from the secured runtime.

Treat these as security invariants.

## Existing swarm lab

Do not immediately delete the existing `docker/swarm/` implementation.

Keep it as a fast deterministic control demonstration until equivalent Strands scenarios are stable.

Document the difference:

```text
docker/swarm/
    deterministic security simulation/regression harness

integrations/strands/
    real agent-runtime integration and adversarial harness
```

Once equivalent production-path Strands tests are reliable, identify which old simulated checks have become redundant.

Do not delete them without clear equivalent coverage.

## Framework neutrality

Do not place Strands-specific concepts into the core Loom policy model unless they represent genuinely generic agent-security concepts.

For example:

GOOD core Loom concepts:

* principal
* workload/agent
* session
* action
* tool
* resource
* provenance
* trust
* destination
* policy decision
* approval
* security event

BAD core Loom concepts:

* Strands-specific internal classes
* Strands event object types
* framework-specific agent-state structures

Create an adapter layer.

Conceptually:

```text
Strands concepts
      ↓
Strands → Loom adapter
      ↓
generic Loom SecurityContext
```

This is necessary so another runtime can later implement:

```text
LangGraph → Loom adapter
```

without changing core policy logic.

## Documentation

Add documentation showing:

### Architecture

```text
Strands
   ↓
Loom
   ↓
Models / Tools
```

### Trusted boundaries

Clearly state:

* Strands agent output is not inherently trusted.
* Strands hooks are not the ultimate authorization boundary.
* MCP servers are not inherently trusted.
* model output is not inherently trusted.
* retrieved content is not inherently trusted.
* Loom policy enforcement is authoritative for protected capabilities.

### Example

Provide one complete secured example showing:

```text
user
 ↓
researcher
 ↓
Loom-mediated file read
 ↓
planner
 ↓
operator requests privileged action
 ↓
Loom policy denies or requires approval
```

Make it possible for a new developer to understand why the design exists.

## Security acceptance criteria

The integration is not complete unless all of these are true:

1. A secured Strands model request flows through Loom.
2. A secured Strands MCP tool request flows through Loom.
3. Unauthorized tools are denied through the real gateway.
4. Agent identity has a representation and enters Loom's security context where technically supported.
5. Provenance survives at least one real agent handoff.
6. Privileged local Strands tools do not bypass Loom.
7. Strands does not contain provider credentials that allow bypassing Loom in the secured runtime.
8. A real multi-agent Strands scenario exercises Loom security.
9. Capability escalation is tested against production enforcement.
10. Delegation/provenance attacks are represented.
11. A runaway agent/swarm has bounded execution.
12. Security-relevant Strands events correlate with Loom traces/security events.
13. Security failures do not cause direct fallback to providers/tools.
14. The Strands runtime container is explicitly hardened.
15. Existing Loom tests continue passing.
16. Existing developer workflows continue functioning.
17. Strands-specific code remains isolated behind an adapter.
18. Loom remains conceptually capable of supporting other agent frameworks.

## Definition of done

At completion, provide:

1. The architecture you implemented.
2. The trust boundaries.
3. The files added and modified.
4. How Strands reaches Loom's LLM gateway.
5. How Strands reaches Loom's MCP gateway.
6. How identity is propagated.
7. How provenance is propagated.
8. Which Strands hooks/interventions are used and why.
9. Which decisions remain authoritative in Loom.
10. Which controls are merely local Strands defense-in-depth.
11. The adversarial scenarios implemented.
12. Which scenarios exercise actual production enforcement.
13. Commands for running the secured reference agent.
14. Commands for running the Strands adversarial lab.
15. Commands for running CI/security tests.
16. Remaining security gaps.
17. Any known ways the Strands process can still bypass Loom.
18. A proposed next phase for eliminating those gaps.

Before completing, perform a hostile architecture review.

Assume:

* the model is malicious,
* retrieved content is malicious,
* an MCP server is malicious,
* one Strands agent is compromised,
* another Strands agent is more privileged,
* the Strands process itself is compromised,
* the workspace contains adversarial content.

Ask:

> Can any of these actors reach a consequential resource, destination, credential, model provider, or tool without crossing an authoritative Loom enforcement point?

If yes, either fix the path or document it explicitly as an unresolved security boundary with a concrete remediation.

Do not claim Loom secures a capability that can still be reached through an unmediated path.
