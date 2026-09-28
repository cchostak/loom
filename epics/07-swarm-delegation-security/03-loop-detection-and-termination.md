# TASK-SD-03: Recursive Swarm Loop Detection & Automated Runaway Termination

## Epic: 07-swarm-delegation-security
**Status**: Ready for Implementation  
**Security Classification**: High (Availability & Cost Control)  
**Relevant Standards**: OWASP Top 10 for LLM (LLM04 - Model DoS), NIST AI RMF  

---

## 1. Context & Tooling Evaluation

Autonomous multi-agent swarms can enter recursive execution loops when interacting with tools or collaborating on sub-tasks (e.g. Agent A asks Agent B for clarification, Agent B calls Agent A back, repeating indefinitely). This causes rapid token exhaustion, connection pool starvation, and runaway infrastructure bills. Loop detection algorithms are critical.

### Tooling Trade-Off Matrix

| Loop Detection Technique | Enterprise Fit | Pros | Cons / Constraints | Selection Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| **Sliding Window Fingerprinting** | High (Real-Time & Fast) | Sub-millisecond hashing of action tuples (Agent + Tool + ArgHash); detects repetitive cycles within sliding window of N actions; low memory footprint. | May not detect complex multi-agent cycles spanning > N steps. | **Selected Baseline Standard**: Deploy sliding window action fingerprinting in swarm controller. |
| **Directed Execution Graph Cycle Analysis** | High (Deep Graph Inspection) | Builds full dependency graph of agent invocations; detects arbitrarily long cycles using Tarjan's / DFS algorithms. | Requires maintaining in-memory session graph; slightly higher compute overhead. | **Recommended for Complex Swarms**: Deploy for swarms with > 5 interacting agents. |
| **Hard Hop & Time Bounds** | High (Universal Safety Net) | Trivial to implement; guarantees termination; bounds maximum resource expenditure. | Crude; terminates long but valid workflows if thresholds are set too aggressively. | **Mandatory Fail-Safe**: Enforce hard limits on total turns (e.g. 25) and execution timeout (e.g. 120s). |

---

## 2. Problem Statement & Threat Vectors

When an LLM receives an unexpected tool error or ambiguous output, it frequently attempts to retry the identical tool call with slight formatting variations. In multi-agent swarms, recursive handoffs between agents can generate hundreds of model queries in seconds, consuming thousands of dollars in tokens and hanging server threads.

### Threat Vectors
- **Runaway Multi-Agent Loops (OWASP LLM04)**: Unbounded recursive calls between collaborating agents.
- **Resource Depletion Attack (CWE-400)**: Adversary providing input designed to trap the agent in an infinite reasoning or tool-retry loop.
- **Cascading Memory Exhaustion**: Accumulating unbounded conversation histories across recursive hops.

---

## 3. Architecture & Technical Blueprint

```text
Swarm Execution State Machine
        │
        ▼ 1. Agent Handoff / Tool Call
Loop Detection Engine (Swarm Runner / Boundary Controller)
        │
        ├── 2. Compute Action Fingerprint:
        │      Fingerprint = SHA-256( CallingAgent || TargetAgent || ToolName || ArgumentsDigest )
        │
        ├── 3. Update Sliding Window (History of last 10 actions)
        │
        ├── 4. Evaluate Termination Conditions:
        │      ├── Condition A: Total workflow hops > MAX_HOPS (e.g. 25 hops)
        │      ├── Condition B: Workflow elapsed time > TIMEOUT (e.g. 120 seconds)
        │      └── Condition C: Cycle detected: Same Fingerprint repeated >= 3 times in window
        │
        ├── 5. IF Any Condition Triggered:
        │      ├── Terminate execution loop immediately (Fail-Fast)
        │      ├── Emit OTel Finding: reason="runaway_loop_detected"
        │      └── Return error to user: "Swarm execution aborted: runaway loop detected"
        │
        ▼ 6. Pass: Admitted to execute next step
```

---

## 4. Implementation Tasks

- [ ] Implement action fingerprinting (SHA-256) on agent-to-agent and tool invocations.
- [ ] Implement sliding window cycle detection tracking repeating action sequences.
- [ ] Enforce hard maximum turn limits and overall workflow execution timeouts.
- [ ] Implement graceful swarm termination with detailed diagnostic error messages.
- [ ] Emit structured telemetry findings when runaway loops are aborted.
- [ ] Add automated unit tests verifying that recursive loops are terminated within 3 cycles.

---

## 5. Definition of Done (DoD) & Acceptance Criteria

1. **Cycle Abort**: Swarms trapped in repetitive tool loops are terminated automatically within 3 repetitions.
2. **Hard Limits**: Workflows exceeding max turn limits or timeout thresholds terminate deterministically.
3. **Audit Visibility**: Aborted runaway loops emit structured compliance findings for cost monitoring.
4. **Automated Verification**: Complete test suite passes: `make strands-test && make strands-lab`.

---

## 6. Verification & Validation Strategy

```bash
# Verify Strands execution bounds and loop handling
make strands-test

# Run complete keyless Strands lab
make strands-lab
```
