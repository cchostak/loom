# ADR 0002: Agentgateway mediation and explicit security boundary

Status: amended 2026-09-23 by the security hardening implementation.

Keep Agentgateway for LLM/MCP routing, request/response webhooks, CEL tool
filtering and traces. Place a separate authenticated policy boundary in front of
its internal listeners. The boundary holds local credential hashes and audit
storage; Agentgateway holds the provider key. The filesystem stdio child starts
with an empty environment and exposes only bounded read/list operations.

Networks separate the IDE, mediation services, inspection services and telemetry.
Only the control-plane APIs, IDE and Jaeger publish loopback ports. The gateway
has provider egress; this is not yet an enforced domain-level egress firewall.

The former ADR incorrectly claimed `blockOnError: true` existed in configuration,
that all ports were localhost-bound, and that pattern matching guaranteed safe
execution. Those claims are withdrawn. Boundary integration tests require an
explicit clean inspection result before dispatch and before releasing results.
The original Agentgateway hooks remain a second check. Policy does not rely on
prompt strings to deny write/execute tools.

See [current architecture and quickstart](../../README.md),
[threat model](../security-threat-model.md), and
[enforcement/test evidence](../security-implementation.md). Local identities,
budgets and audit storage require production replacements before shared use.
