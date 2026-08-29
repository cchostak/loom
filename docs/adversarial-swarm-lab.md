# Adversarial Agent Swarm Lab

Loom includes a deterministic, keyless lab for demonstrating how attacks can
propagate across cooperating agents and where gateway controls stop them.

## Run it

```bash
make lab
```

The command starts only the local guardrail service, builds an isolated lab
runner, and compares every scenario twice:

1. An intentionally unprotected baseline, which proves the attack chain can
   reach its objective.
2. A defended run through Loom's live Agentgateway-compatible request and
   response webhook API, least-privilege capability policy, and delegation
   trust boundary.

No LLM provider key is required. The scenarios never run shell commands,
change files, or send data to an external endpoint. Use `make lab-json` to emit
a report suitable for CI evidence.

## Included scenarios

| Scenario | Swarm failure mode | Expected control |
| --- | --- | --- |
| `indirect-prompt-injection` | A scout carries poisoned third-party content to a planner | Content guardrail |
| `capability-escalation` | A worker calls a tool outside its capability envelope | Least-privilege capability policy |
| `delegation-laundering` | Untrusted context is promoted to a publishing agent | Delegation trust boundary |
| `cross-agent-exfiltration` | A compromised agent returns an exfiltration instruction | Response content guardrail |

## What the score means

`Attack chains blocked` is the fraction of scenarios that compromise the
unprotected baseline but do not compromise the defended run. The score is a
repeatable control demonstration, not a claim that regex filtering proves an
agent system safe. Extend the scenario catalog and replace deterministic
payloads with model-driven red-team agents before using it as an evaluation of
a production swarm.

## Safety model

- All attack payloads are inert strings.
- The lab runner is an unprivileged, short-lived container.
- The runner calls only the guardrail service and has no tool or workspace mounts.
- A guardrail connectivity or protocol error fails the lab closed.
- Capability and delegation decisions are explicit and recorded per event.

The lab's reusable engine lives in `docker/swarm/`; the CLI entry point is
`docker/cmd/swarm-lab/`. Add scenarios in `docker/swarm/scenarios.go` and add a
unit test for every new control or branch.
