# TASK-MC-04: Multi-Tenant Workload Runtime Isolation & Kernel Virtualization

## Epic: 02-mcp-tool-containment
**Status**: Ready for Implementation  
**Security Classification**: High (Container Sandbox & Kernel Hardening)  
**Relevant Standards**: OCI Runtime Specification, CIS Docker Benchmark, NIST SP 800-190  

---

## 1. Context & Tooling Evaluation

When an AI agent executes dynamic Python code, shell commands, or third-party MCP servers, standard Linux container isolation (`runc`) is insufficient. If a zero-day Linux kernel vulnerability is exploited, the adversary achieves host compromise. Workload runtime sandboxing provides hardware or user-space kernel virtualization.

### Tooling Trade-Off Matrix

| Isolation Technology | Enterprise Fit | Pros | Cons / Constraints | Selection Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| **gVisor (`runsc`)** | High (Application Virtualization) | Intercepts Linux syscalls in user-space Sentry; fast startup (< 50ms); minimal memory overhead; native Docker/OCI plugin. | Moderate I/O latency penalty on high-frequency file reads/writes. | **Selected Baseline Standard**: Ideal for untrusted agent scripts and MCP tool execution containers. |
| **Kata Containers** | High (Hardware Virtualization) | Dedicated lightweight VM kernel per container; complete hardware-level memory/CPU boundary. | Higher memory footprint (~128MB per container); requires nested virtualization support in cloud VMs. | **Recommended for Multi-Tenant Cloud**: Use where tenant data cannot share a Linux kernel under any circumstance. |
| **AWS Firecracker** | High (Serverless Micro-VM) | Minimalist VMM; ultra-fast boot (< 5ms); proven at hyperscale (AWS Lambda/Fargate). | Requires custom rootfs orchestration; not a drop-in Docker Compose OCI runtime without wrapper plugins. | **Cloud Infrastructure Option**: Best suited for dedicated enterprise agent execution pools on AWS. |
| **Standard Linux Container (`runc`)** | Low (Insufficient Boundary) | Zero overhead; native performance; universal compatibility. | Direct exposure of ~350+ host kernel syscalls; vulnerable to kernel privilege escalation breakouts. | **Restricted**: Acceptable only for trusted internal control plane components. |

---

## 2. Problem Statement & Threat Vectors

AI agent workflows often require executing generated code, parsing arbitrary binary files, or running open-source MCP adapters. A vulnerability in an underlying library (e.g. ImageMagick, libxml, Python interpreter bug) can grant an attacker arbitrary code execution inside the container. In standard Docker, this permits probing and exploiting host kernel vulnerabilities.

### Threat Vectors
- **Kernel Privilege Escalation (CWE-250)**: Exploiting host kernel vulnerabilities to gain root on the underlying VM or bare-metal host.
- **Side-Channel & Cache Attacks (CWE-200)**: Probing memory or CPU cache states of adjacent tenant containers.
- **Host Resource Starvation (CWE-400)**: Consuming all available file descriptors, PIDs, or kernel memory.

---

## 3. Architecture & Technical Blueprint

```text
Untrusted MCP Tool / Python Agent Worker
        │
        ▼ Syscalls (read, openat, clone, socket, ptrace)
User-Space Kernel Virtualization (gVisor runsc Sentry)
        │
        ├── 1. Virtualizes Linux kernel syscall table in user-space
        ├── 2. Blocks hostile syscalls (raw sockets, unshare, bpf, ptrace)
        ├── 3. Isolates memory allocations from host physical memory
        └── 4. Mediates filesystem operations via Gofer process
        │
        ▼ Restricted, Sanitized Syscalls Only
Host Linux Kernel
```

---

## 4. Implementation Tasks

- [ ] Create runtime installation and setup scripts for `runsc` (gVisor).
- [ ] Configure Docker daemon to register `runsc` and `kata` runtimes in `/etc/docker/daemon.json`.
- [ ] Assign `runtime: runsc` to untrusted agent containers and tool execution sandboxes in Compose.
- [ ] Implement pre-flight environment checks detecting runtime registration.
- [ ] Verify isolated execution and resource constraints with automated test suites.

---

## 5. Definition of Done (DoD) & Acceptance Criteria

1. **Syscall Interception**: Untrusted containers run with gVisor user-space kernel virtualization.
2. **Blocked Primitives**: Dangerous syscalls (`ptrace`, `bpf`, `unshare`) are blocked inside the container.
3. **Host Inaccessibility**: Host system files and adjacent container state remain inaccessible even if root is compromised inside the sandbox.
4. **Automated Health Check**: Environment pre-flight check validates runtime presence without errors.

---

## 6. Verification & Validation Strategy

```bash
# Verify runtime registration and environment health
make doctor

# Execute isolated execution sandbox test
make strands-lab
```
