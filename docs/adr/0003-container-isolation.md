# ADR 0003 — Container Isolation Strategy

**Date:** 2026-09-22
**Status:** Accepted; amended 2026-09-23
**Deciders:** Loom maintainers

---

## Context

The Loom stack processes untrusted content on three surfaces:

1. **`guardrail-proxy`** — receives raw LLM prompts and responses, runs
   forbidden-pattern matching, and calls Presidio for PII analysis.
2. **`presidio-analyzer`** — Python/spaCy ML service that tokenizes and
   classifies arbitrary text.
3. **`agentgateway`** — routes all LLM traffic and holds the `OPENROUTER_API_KEY`.

Docker's default runtime (`runc`) provides namespace and cgroup isolation but
shares the host Linux kernel. A kernel exploit embedded in adversarial prompt
content, a malicious ML model, or a supply-chain compromise in the Python
dependency tree could escalate to the host.

The host has:
- KVM available (`/dev/kvm`)
- AppArmor + seccomp already active (Docker defaults)
- Kernel 7.x

We evaluated three deep isolation options.

---

## Options Considered

### Option A — gVisor (`runsc`)

gVisor interposes all syscalls between the container process and the Linux
kernel. It implements a substantial portion of the Linux syscall ABI in
userspace (the "Sentry"), backed by a very small footprint of actual kernel
calls. A kernel exploit from within the container hits the Sentry, not the host
kernel.

**Pros:**
- Transparent to Docker Compose (`runtime: runsc` per service).
- No VM overhead; container start time is comparable to `runc`.
- ~5–15% CPU overhead from syscall interposition.
- Supports both `systrap` (pure userspace) and `kvm` platform modes.

**Cons:**
- Does not provide a separate kernel; the host kernel is still reachable via
  the tiny Sentry footprint.
- Some syscalls are unimplemented or behave differently (e.g. `ptrace`,
  `perf_event_open`, some `io_uring` operations).
- Verified compatible with `presidio-analyzer` (Python/Flask/spaCy) via a
  compat test in `setup-isolation.sh`.

### Option B — Kata Containers

Kata runs each container inside a lightweight QEMU microVM with its own Linux
kernel. The container process is fully kernel-isolated from the host.

**Pros:**
- True VM-level kernel isolation — strongest available without full VMs.
- Compatible with existing OCI images.

**Cons:**
- ~100–200 MB RAM overhead per container.
- ~1 s additional start time per container.
- Requires KVM and QEMU; adds a complex host dependency.
- Volume mounts (needed by `vscode`) require virtio-fs or 9p, adding
  configuration complexity.

### Option C — Firecracker

AWS Firecracker provides sub-second microVM boot and minimal overhead.

**Cons:**
- Does not integrate with Docker directly. Requires `firecracker-containerd`,
  which replaces the containerd shim — too invasive for a local dev stack.
- Not viable without replacing the Docker runtime layer entirely.

### Option D — Bottlerocket

A hardened container-optimized host OS from AWS.

**Cons:**
- A host OS, not a container runtime. Incompatible with a Docker Compose
  local dev workflow on an existing workstation.

---

## Decision

**Use gVisor (`runsc`) for the four security-sensitive services** via an
opt-in compose override (`docker-compose.isolation.yml`).

| Service | Runtime | Reason |
|---|---|---|
| `control-plane` | `runsc` | Authenticates, authorizes and audits untrusted requests |
| `guardrail-proxy` | `runsc` | Processes untrusted LLM content |
| `presidio-analyzer` | `runsc` | Processes PII-laden text; broad Python syscall surface |
| `agentgateway` | `runsc` | Holds the API key and routes all LLM traffic |
| `vscode` | `runc` | Writable developer environment; optional isolation requires compatibility testing |
| `otel-collector` | `runc` | Internal telemetry ingestion; still processes untrusted data |
| `jaeger` | `runc` | Loopback UI and internal telemetry; still an attack surface |

The isolation is opt-in (not the default `make up`) so contributors without
gVisor installed are not blocked. CI runs on GitHub Actions runners that do not
support gVisor; no CI changes are required.

**Upgrade path for `vscode`:** if stronger isolation of the IDE is required,
Kata Containers with virtio-fs is the correct next step. This is not done
by default due to the added RAM overhead and volume-mount complexity.

---

## Consequences

- Running `make setup-isolation` is a one-time host-level change that modifies
  `/etc/docker/daemon.json` and installs `/usr/local/bin/runsc`.
- `make up-isolated` enforces that `runsc` is registered before attempting
  to start the stack.
- `make doctor` reports the registered isolation runtimes.
- The `setup-isolation.sh` script performs a gVisor compatibility test against
  the `presidio-analyzer` image before committing to the daemon configuration.
- The `--with-kata` flag on `setup-isolation.sh` installs Kata Containers for
  future use (e.g. to sandbox `vscode`).

## Current validation limits

The hardening work validated the default Docker runtime, not gVisor or Kata.
The host characteristics and performance estimates above describe the original
proposal, not portable requirements or evidence for the current images. An
optional sandbox adds a boundary; it does not guarantee containment or eliminate
host-volume, provider-key, telemetry or network-egress risks. See the current
[threat model](../security-threat-model.md) for those boundaries.
