# Secured Strands reference runtime

Strands proposes actions. Loom authenticates the caller and decides which model
and MCP requests may run. This integration uses Strands Agents 1.57.0, with a
locked Python 3.14 dependency graph, a digest-pinned minimal Chainguard image, and an optional Docker Compose `agents` profile.

## Run it

Install Docker Compose with `!override` support and `uv` 0.12.18, then from the
repository root:

```sh
make init
make strands-test
make strands-lab
```

The lab needs no provider key. It starts a separate `loom-strands-lab` Compose
project with a deterministic provider behind the real Agentgateway. Production
MCP, authentication, policy, filesystem checks and guardrails remain active.
The existing development stack is not redirected. Allow several minutes for the
first build and the Presidio model to start.

For a real-model demonstration, set `OPENROUTER_API_KEY` and `IDE_PASSWORD` in
`.env`, put non-sensitive example files in `workspace/`, then run:

```sh
make strands
```

Only Agentgateway receives the provider key. Each agent container receives one
role-specific Loom credential. The demo runs researcher → planner; the adversarial
lab additionally exercises operator and publisher. The lab reports content-free
JSON events and checks their decision/trace IDs against Loom audit and Jaeger.
It does not print prompts, file contents, handoff contents or tokens.

Stop only the lab with:

```sh
docker compose -p loom-strands-lab -f docker-compose.yml \
  -f integrations/strands/compose.lab.yml --profile agents down
```

Local credentials expire after seven days. Bootstrap checks consistency and does
not silently rotate them. Follow the repository's local identity recovery process
before provisioning a replacement; preserve unrelated identities. Repeated runs
share each role's server-side session budget, so rapid reruns may correctly be
throttled. Budgets are not reset by changing a client workflow ID.

## Request path and roles

```text
host workflow runner (trusted developer tooling)
    → isolated Strands role process
        → authenticated Loom control-plane:8080
            → Agentgateway LLM → guarded model provider
            → Agentgateway MCP → isolated read-only filesystem
```

| Role | Model | Filesystem |
| --- | --- | --- |
| researcher | Configured model only | Read and list workspace |
| planner | Configured model only | None |
| operator | Configured model only | List workspace only |
| publisher | Configured model only | None; publishing unavailable |

All roles may initialize MCP and discover tools. Discovery is not a grant.
Native Strands MCP tools are registered only where useful. `request_capability`
is a narrow adapter that sends an MCP proposal to Loom, including unsupported
names for denial demonstrations. It has no shell, filesystem or external HTTP
implementation. Loom independently checks every proposal, including calls made
by a process that skips hooks entirely.

`LoomModel` translates bounded text completions into native Strands text/tool-use
events. Models must return one object containing either `text` or `tool` and
`input`. Tool calls and results are serialized into the existing text protocol;
streaming, multimedia, provider tool-calling extensions and arbitrary endpoints
are unsupported. The MCP adapter uses Strands MCPClient with a POST-only transport;
an authenticated, owned DELETE releases each session on exit. Server-initiated
sampling, subscriptions, resumption and subprocess transports are
not available. Malformed responses fail closed.

## Trust and observations

Agents, model responses, file contents and MCP responses are untrusted.
`DataContext` preserves source, producer, origin, parents, taint and sensitivity
through real process handoffs. Compiled system instructions are separate from
handoff data, but do not grant authorization. Client lineage is descriptive,
not signed evidence. Loom independently treats all ingress as untrusted.

BeforeModelCall, BeforeToolCall and AfterToolCall hooks bound local execution,
record transitions and conservatively extend lineage. They do not authorize
anything. All roles share the same framework-neutral Go policy contracts.
The host runner bounds handoffs and kills timed-out one-shot containers. A failed
or interrupted process never commits a handoff.

Events distinguish an attempted request, HTTP acceptance/rejection and a Strands
tool result. HTTP success alone does not establish successful tool execution.
Loom's durable audit is authoritative; client events are not trustworthy after a
process compromise. Server-generated trace IDs link to the existing privacy-filtered
Jaeger traces. SDK prompt/content telemetry is disabled.

Approval, guidance and transformation are not production Loom protocols today.
A non-success response stops the adapter; it never synthesizes approval, resumes
an action with extra privileges or returns an uninspected replacement. The tested
Go approval library alone is not an operator approval service.

## Limits and failure behavior

Local controls: six model turns, four tool calls, four handoff levels, 90 seconds
per agent, 120-second host process timeout, 64 KiB requests, 1 MiB responses,
16,000-character handoffs and 1,024 requested output tokens. These are safety
controls that a compromised interpreter could skip. Loom independently enforces
its per-session operations, rate, concurrency, lifetime, input and output limits.
Container CPU, memory, process and file-descriptor limits constrain the process.

Unavailable gateways, denials, redirects, malformed responses and timeouts have
no direct-provider or direct-tool fallback. Tool errors stop the reference workflow; they never commit a new handoff. Local event
capacity failures stop execution; telemetry export availability does not change
policy. Core audit failure prevents dispatch independently of client telemetry.

## What the lab proves

The fixture scripts model proposals, not security decisions. Actual Strands
invocations make authenticated model and MCP requests. The lab checks benign
reads, indirect instructions carried in retrieved content, capability escalation,
low-privilege-to-higher-privilege delegation, inert external publication requests,
path traversal and a repeating agent. No policy dictionary decides their outcome.

Container checks attempt direct TCP access to raw gateway, tool-adjacent services,
fixture provider, Internet and metadata addresses. They also check DNS containment,
role secret separation, mounts, hardening and absence of shells/provider credentials.
Unit fixtures separately exercise protocol failures and interrupted handoffs.

`docker/swarm/` remains the fast simulation/regression harness. Its simulated
capability/delegation checks now have Strands production-path counterparts; it is
retained because the two suites exercise different layers.

See [the architecture and hostile review](../../docs/strands-integration.md) for
security limitations and the next phase. This is a local reference runtime, not
a claim of general confidential-data protection or container-escape resistance.
