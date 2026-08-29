# Contributing to Loom

Thank you for your interest in contributing to Loom! This document outlines our development guidelines, branch strategy, commit conventions, testing standards, and pull request workflow.

---

## 1. Prerequisites & Tooling

Ensure you have the following tools installed locally:

- **Docker & Docker Compose**: Docker Engine 24.0+ / Docker Compose v2.20+
- **Go**: Version 1.22+ (for developing and testing the guardrail proxy)
- **Make**: GNU Make 4.0+
- **Git**: Version 2.30+
- **pre-commit** *(recommended)*: For automated local linting and secret scanning (`pip install pre-commit`)
- **curl**: For executing smoke test scripts

Run the built-in diagnostic tool to verify your environment:

```bash
make doctor
```

---

## 2. Quickstart & Local Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/cchostak/loom.git
   cd loom
   ```

2. **Initialize configuration template:**
   ```bash
   make init
   ```
   *Edit `.env` to configure `OPENROUTER_API_KEY` and `IDE_PASSWORD`.*

3. **Install pre-commit hooks:**
   ```bash
   pre-commit install
   ```

4. **Launch the local containerized stack:**
   ```bash
   make up
   ```

5. **Verify service health:**
   ```bash
   make test-smoke
   ```

---

## 3. Git Branching & Conventional Commits

### Branch Naming Conventions
- `feat/<short-description>`: New features or capabilities (e.g., `feat/add-trivy-scanner`)
- `fix/<short-description>`: Bug fixes and security patches (e.g., `fix/guardrail-regex-boundary`)
- `chore/<short-description>`: Tooling, dependency updates, and maintenance (e.g., `chore/bump-go-1.22`)
- `docs/<short-description>`: Documentation changes and ADRs (e.g., `docs/add-cel-policy-guide`)
- `sec/<short-description>`: Security enhancements and hardening (e.g., `sec/remediate-gitleaks-finding`)

### Commit Messages (Conventional Commits)
We follow the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) standard:

```
<type>(<optional scope>): <subject>

[optional body]

[optional footer(s)]
```

**Allowed types:** `feat`, `fix`, `chore`, `ci`, `docs`, `refactor`, `perf`, `test`, `sec`.

**Examples:**
- `feat(guardrail): support streaming JSON message token validation`
- `fix(gateway): resolve timeout issue during high concurrency upstream queries`
- `docs(adr): record ADR-0002 for containerized IDE architecture`
- `ci(actions): add gitleaks and trivy automated security scan workflows`

---

## 4. Coding, Formatting & Linting Standards

All contributions must adhere to repository linting and formatting rules:

- **Go**:
  - Run `make fmt` to format Go code with standard `gofmt`.
  - Run `make check` to execute `go vet` and static analyzers.
- **YAML & Markdown**:
  - 2-space indentation, max line length 180 characters for YAML.
  - Formatted cleanly without trailing whitespaces.
- **Shell Scripts**:
  - POSIX compliance, strict mode (`set -euo pipefail`), ShellCheck clean.
- **Dockerfiles**:
  - Multi-stage builds, non-root users where possible, Hadolint compliant.

---

## 5. Testing Requirements

Every code change must include accompanying automated tests:

1. **Unit Tests**:
   - Run local unit tests with race detection and coverage:
     ```bash
     make test
     ```
   - All tests in `docker/*_test.go` must pass.

2. **Integration / Smoke Tests**:
   - Execute the end-to-end smoke test suite against running containers:
     ```bash
     make test-smoke
     ```

3. **Security Audits**:
   - Verify that no secrets or vulnerabilities are introduced:
     ```bash
     make scan
     ```

---

## 6. Pull Request Lifecycle

1. Ensure all branch changes pass local checks:
   ```bash
   make check
   make test
   ```
2. Push your feature branch and open a Pull Request against `main`.
3. Provide a clear PR description detailing:
   - What changed and why.
   - Any architectural implications or configuration changes.
   - Proof of testing (command outputs or test run logs).
4. CI checks (`ci.yml` and `security.yml`) must pass before review.
5. Address reviewer comments promptly and rebase if conflicts arise.
6. Squash-and-merge is performed once approved by code owners.
