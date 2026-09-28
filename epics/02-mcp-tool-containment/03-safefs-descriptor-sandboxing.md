# TASK-MC-03: Kernel-Level Descriptor-Relative Sandboxing for Filesystem Tools

## Epic: 02-mcp-tool-containment
**Status**: Ready for Implementation  
**Security Classification**: Critical (Filesystem Sandboxing & Escape Prevention)  
**Relevant Standards**: POSIX.1-2008 (`openat`), Linux `openat2(2)` (`RESOLVE_BENEATH`), OWASP Top 10 (CWE-22, CWE-59)  

---

## 1. Context & Tooling Evaluation

Filesystem tools (`read_text_file`, `write_file`, `list_directory`) are among the most dangerous capabilities exposed to AI agents. User-space path validation (e.g. checking if a path starts with `/workspace`) is inherently flawed due to Time-of-Check to Time-of-Use (TOCTOU) symlink races. Kernel-enforced sandboxing is required.

### Tooling Trade-Off Matrix

| Sandboxing Technology | Enterprise Fit | Pros | Cons / Constraints | Selection Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| **POSIX Descriptor-Relative (`openat` / `O_NOFOLLOW`)** | High (Universal POSIX) | Kernel-enforced, portable across all Linux kernels, eliminates symlink traversal, negligible overhead. | Requires tracking root directory file descriptors in process state. | **Selected Baseline Standard**: Deploy in core `safefs` Go implementation. |
| **Linux `openat2` (`RESOLVE_BENEATH`)** | High (Modern Linux $\ge 5.6$) | Strict kernel guarantee that path resolution never crosses root fd, even across complex multi-component symlinks. | Requires Linux kernel $\ge 5.6$; requires syscall fallback on older container hosts. | **Recommended Enhancement**: Use where modern Linux kernels are available. |
| **Linux Landlock LSM** | High (Unprivileged Sandboxing) | Granular access rights enforced per process thread; unprivileged processes can restrict their own access. | Requires Linux $\ge 5.13$; container runtime must allow Landlock syscalls. | **Supplemental**: Apply at tool process initialization. |
| **String-Based Path Checks (`filepath.Clean`)** | Low (Vulnerable) | Trivial to implement with standard library functions. | Vulnerable to TOCTOU symlink races; susceptible to encoding and Unicode normalization bypasses. | **Anti-Pattern**: Insufficient as a primary boundary defense. |

---

## 2. Problem Statement & Threat Vectors

An AI agent tricked by prompt injection can be coerced into reading or writing files outside the designated workspace (e.g. `/etc/passwd`, `/etc/shadow`, container environment variables with API keys). Symlinks created dynamically inside the workspace directory can trick naive string validators into opening files on the host root filesystem.

### Threat Vectors
- **Symlink Directory Traversal (CWE-59)**: Symlink created inside `/workspace` pointing to sensitive host paths.
- **TOCTOU Race Condition (CWE-367)**: Replacing a benign file with a symlink between path validation and `os.Open`.
- **Absolute Path Resolution Escapes (CWE-22)**: Utilizing alternative encodings or null bytes to escape prefix matching.

---

## 3. Architecture & Technical Blueprint

```text
MCP Client Tool Request ("read_text_file", path: "/workspace/logs/../../etc/passwd")
        │
        ▼ 1. Pre-Execution Filter (ExtAuthz)
ExtAuthz Perimeter Check: Rejects "..", "\", control chars, paths outside /workspace
        │
        ▼ 2. Dispatches to SafeFS Worker Service
SafeFS Boundary Handler (docker/safefs/)
        │
        ├── 3. Open Root Directory Descriptor:
        │      rootFd = syscall.Open("/workspace", O_DIRECTORY | O_PATH)
        │
        ├── 4. Kernel-Level Descriptor Resolution:
        │      fd = syscall.Openat(rootFd, relativePath, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        │
        ├── 5. Kernel Evaluation:
        │      ├── IF path traverses outside rootFd OR touches symlink:
        │      │      └── Kernel returns ELOOP or EXDEV -> Blocked with 403 Forbidden
        │      └── IF valid file beneath rootFd:
        │             └── Kernel returns active file descriptor -> Safe read
        │
        ▼ 6. Return sanitized file content to caller
```

---

## 4. Implementation Tasks

- [ ] Implement `safefs` package in Go using descriptor-relative `openat` and `O_NOFOLLOW`.
- [ ] Implement pre-flight path sanitization in ExtAuthz rejecting `..`, `\`, and non-printable characters.
- [ ] Confine all filesystem operations strictly within the root workspace directory descriptor.
- [ ] Add regression tests exercising symlink attacks, directory traversal payloads, and race condition attempts.

---

## 5. Definition of Done (DoD) & Acceptance Criteria

1. **Kernel-Level Confinement**: Any attempt to open files outside the root directory descriptor fails at the kernel level.
2. **Symlink Rejection**: Resolving paths containing symlinks pointing outside the workspace fails with `403 Forbidden`.
3. **Defense-in-Depth**: ExtAuthz perimeter rejects path traversal sequences before reaching the filesystem handler.
4. **Performance Standard**: Descriptor resolution overhead is indistinguishable from standard `os.Open` (< 50μs).
5. **Automated Verification**: Complete test suite passes verifying isolation against known traversal attacks.

---

## 6. Verification & Validation Strategy

```bash
# Verify SafeFS and ExtAuthz path traversal defenses
cd docker && go test -v -race ./safefs
cd docker && go test -v -race -run TestExtAuthz_PathTraversal ./security
```
