# Loom security threat model

Assessment: 2026-09-23. Scope includes Compose, Go webhooks, Agentgateway,
stdio MCP, the optional Python ingestion pipeline, swarm simulation, and CI.
This is a local developer deployment, not a multi-tenant production service.

## Assets, actors and boundaries

Assets: provider credentials, workspace contents, prompts and responses, raw
Bronze documents, derived context, security policy, identities, budget state,
audit events and CI signing authority. Actors include developers, agents,
external content authors, model providers, MCP implementations, CI contributors,
and operators. Treat models, files, tools and retrieved material as untrusted.

Boundaries: browser/IDE to ingress; ingress to Agentgateway; gateway to model
provider; gateway to guardrails/Presidio; gateway to MCP execution; workspace
mount to host; ingestion storage to model consumption; telemetry to operators;
untrusted PR to privileged build/release jobs. A Docker bridge is connectivity,
not authentication. A writable workspace is attacker-controlled data.

Ingress includes HTTP prompts, MCP arguments, files, tool results, retrieval,
configuration, environment and PRs. Egress includes OpenRouter, MCP results,
traces/logs, IDE networking and optional embedding downloads. Reads can export
secrets; writes, shell execution, deployments and external messages are
privileged even when phrased as harmless natural-language requests.

## Original controls and gaps

Useful controls: Agentgateway request/response hooks, CEL tool default deny,
1 MiB webhook body bound, deterministic/keyless swarm scenarios and tracing.
The original configuration exposed HTTP/OTLP ports on every host interface,
ran gateway and guardrails as root, mounted the workspace writable in the key
holder and launched npm-based MCP code there. Identity was absent. Tool grants
ignored resources and arguments. PII was scrubbed for inspection but original
content was forwarded; analyzer and ingestion failures could allow data through.
CI vulnerability scanning returned success for findings. Documentation claimed
localhost binding and fail-closed behavior without matching runtime evidence.
The lab's capability/delegation checks were simulations, not runtime controls.

## Abuse cases and invariants

* Spoofed identity/confused deputy: authenticate before policy, strip inbound
  identity/credential headers before forwarding, bind identity to a credential.
* Injection/tool misuse: untrusted content cannot grant tool capability. Unknown
  methods, tools, identities and destinations deny; arguments are schema checked.
* Traversal/races: workspace reads use an OS-rooted file API at execution time;
  never authorize a path then open an unconstrained path. No tool writes/exec.
* Exfiltration: secret/PII detectors reject rather than claiming to transform
  bytes which are still forwarded. Detector failure rejects. No raw bodies,
  headers, errors or arguments in security events.
* Resource exhaustion: bound input/output, concurrency, session calls, request
  rate, workflow age and action duration. Clients cannot reset budgets by
  inventing a session header.
* Laundering: data provenance retains untrusted classification on transformation;
  no production delegation grant exists in this increment.
* Fail open: unavailable/malformed policy, auth or guardrail responses deny.
  Audit write failure prevents dispatch. Trace loss is not authorization loss.
* Supply chain: immutable action pins, enforced vulnerability thresholds,
  image scans and build metadata; no runtime dependency acquisition for MCP.

## Residual compromise scenarios

Host/root or a compromised IDE can read its mounted workspace and use its own
network/credentials outside Loom. Gateway compromise can use its provider key
and bypass the application boundary from inside its network. Local audit storage
can be changed by the host. Regex/Presidio are fallible detectors, not proof of
confidentiality. A malicious file can carry instructions even when reads are
properly scoped. Review docs/security-roadmap.md before production deployment.
