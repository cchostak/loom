# AGENTS.md — Global Engineering Policy

> Canonical personal policy for coding agents.
> Project-local instructions may refine or override this file.
> Last reviewed: 2026-09-15

## 0. Normative language

The words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are intentional.

The purpose of this file is to externalize recurring engineering expectations so they do not need to be re-explained in every task.

## 1. Instruction precedence

When instructions conflict, use this order:

1. Explicit instructions in the current task.
2. Project-local `AGENTS.md`, `CONTRIBUTING.md`, architecture decisions, and repository documentation.
3. Existing executable project configuration: CI, formatter, linter, compiler, test runner, package manager, build files.
4. This global policy.
5. The external references listed below.
6. Agent defaults.

Do not rewrite working project conventions merely to make them match this global file.

If a conflict materially changes architecture, compatibility, security, data, or public APIs, call it out before proceeding.

## 2. First actions in every repository

Before editing code, inspect the repository and determine:

- language(s), framework(s), package manager(s), and runtime versions;
- build, test, lint, format, type-check, and code-generation commands;
- CI workflows and release process;
- repository-specific instructions;
- existing architecture and naming conventions;
- whether the requested change touches a public API, persistent data, security boundary, network protocol, or deployment contract.

Prefer existing repository tooling over introducing new tooling.

Do not switch package managers, test frameworks, formatters, linters, build systems, or deployment tools without an explicit reason.

## 3. Change discipline

MUST:

- make the smallest coherent change that fully solves the task;
- preserve existing behavior unless the task requires changing it;
- preserve public APIs and data compatibility unless a breaking change is explicitly required;
- add or update tests for behavioral changes;
- add a regression test for every bug fix when practical;
- keep generated files generated rather than hand-edited;
- keep secrets, credentials, tokens, and private keys out of source control;
- explain non-obvious decisions in code, tests, documentation, or an ADR.

MUST NOT:

- perform unrelated refactors;
- add speculative abstractions;
- introduce a dependency when the standard library or an existing dependency is sufficient;
- silence failing tests or weaken assertions merely to make CI green;
- delete validation, error handling, observability, or safety checks without understanding why they exist.

Prefer boring, explicit, maintainable code over clever code.

## 4. Testing policy — SQLite-inspired

Reference: https://www.sqlite.org/testing.html

The SQLite testing philosophy is a model for **depth, adversarial thinking, regression discipline, and independent verification**. Do not blindly copy SQLite's exact harnesses or coverage targets into every project.

### 4.1 Every behavioral change

MUST test:

- the normal success path;
- relevant error paths;
- boundaries and edge values;
- the bug or regression being fixed;
- externally visible behavior rather than only implementation details.

### 4.2 Risk-weighted deeper testing

For parsers, serializers, storage engines, protocol handlers, security-sensitive code, concurrent code, and code that processes untrusted input, SHOULD consider:

- fuzz testing;
- property-based testing;
- malformed-input testing;
- boundary-value testing;
- concurrency/stress testing;
- crash/restart or interruption testing;
- resource-leak testing;
- sanitizer or undefined-behavior checks where the language/runtime supports them;
- fault injection for I/O, network, allocation, timeout, or dependency failures;
- mutation testing for critical logic when practical.

### 4.3 Regression rule

A bug is not considered fully fixed until a test exists that fails before the fix and passes after it, unless there is a documented reason the behavior cannot be tested automatically.

### 4.4 Test tiers

Prefer a layered test workflow:

- **fast loop**: focused tests, lint, formatting, type checks;
- **normal CI**: complete unit/integration suite;
- **deep reliability**: fuzz, soak, stress, fault-injection, compatibility, and platform matrices where justified.

Do not force expensive deep tests into every local edit loop.

### 4.5 Coverage

Coverage is evidence, not the goal.

For critical logic, prefer meaningful branch/condition coverage over superficial line coverage. Do not add meaningless tests solely to increase a percentage.

## 5. Code style — Google-style default

Reference: https://google.github.io/styleguide/

Google publishes language-specific style guides because consistent code is easier to understand at scale.

Applicability rule:

1. Existing project formatter/linter/style is authoritative.
2. If the project has no explicit style, use the relevant Google style guide for the language when one exists.
3. Prefer automated formatting and linting over manual style arguments.
4. Keep style-only changes separate from behavioral changes when doing so materially improves reviewability.

Relevant guides include C++, C#, Go, HTML/CSS, Java, JavaScript, JSON, Markdown, Python, Shell, Swift, TypeScript, and others.

Do not cargo-cult a Google rule that conflicts with the idioms of the project, language version, framework, or established public API.

## 6. Service architecture — Twelve-Factor default where applicable

Reference: https://12factor.net/

Apply this section to deployable services and SaaS-style applications. Do not force Twelve-Factor rules onto libraries, firmware, desktop applications, one-shot scripts, or other software where the model is inappropriate.

For services, SHOULD follow these principles unless the project has a documented reason not to:

1. **Codebase** — one version-controlled codebase, many deploys.
2. **Dependencies** — explicitly declare and isolate dependencies.
3. **Config** — keep deploy-specific configuration out of source code; use environment/config injection appropriate to the platform.
4. **Backing services** — treat databases, queues, caches, object stores, and external APIs as attached resources.
5. **Build / release / run** — keep build artifacts, release configuration, and runtime execution conceptually separate.
6. **Processes** — prefer stateless processes; keep durable state in backing services.
7. **Port binding** — services should expose themselves through an explicit network interface rather than relying on hidden container/server coupling.
8. **Concurrency** — scale through explicit process/workload concurrency.
9. **Disposability** — support fast startup, graceful shutdown, retries, and interruption.
10. **Dev/prod parity** — minimize environment drift.
11. **Logs** — emit structured/event-oriented logs to standard streams or the platform logging interface; do not make the application responsible for managing log-file lifecycle unless required.
12. **Admin processes** — run migrations, repair jobs, shells, and administrative tasks as explicit one-off processes using the same release/runtime environment.

Modern platform-specific security or orchestration requirements may refine these principles.

## 7. Cloud-native technology selection — CNCF landscape as a decision aid

Reference: https://landscape.cncf.io/

The CNCF Landscape is an ecosystem map, not a mandate to use Kubernetes or to maximize the number of cloud-native components.

When selecting infrastructure for orchestration, observability, service networking, storage, secrets, policy, CI/CD, registries, messaging, or other cloud-native concerns:

- first check whether the project already has a suitable component;
- prefer reducing platform/tool sprawl over adding another product;
- evaluate established CNCF projects before inventing bespoke infrastructure;
- when fit is otherwise comparable, prefer a mature project over an experimental one;
- treat CNCF **Graduated** as a stronger maturity signal than **Incubating**, and **Incubating** as a stronger maturity signal than **Sandbox**;
- do not treat landscape inclusion, foundation membership, popularity, or logo presence as proof that a tool is correct for the project;
- evaluate operational burden, portability, security, ecosystem health, upgrade path, observability, failure modes, and team competence;
- record significant platform choices in an ADR or equivalent decision record.

Prefer the simplest technology that satisfies the actual requirements.

## 8. Design patterns

Design patterns are vocabulary, not objectives.

Use a pattern only when it reduces complexity, coupling, duplication, or change cost.

Typical signals:

- **Strategy** — interchangeable algorithms or policies.
- **Adapter** — reconcile incompatible interfaces.
- **Facade** — simplify access to a complex subsystem.
- **Observer** — one-to-many event notification where loose coupling is valuable.
- **State** — behavior changes materially with explicit object state.
- **Composite** — uniform treatment of tree/part-whole structures.
- **Proxy** — controlled, lazy, remote, cached, or instrumented access to another object.
- **Bridge** — abstraction and implementation need to vary independently.
- **Flyweight** — many similar objects create a demonstrated memory problem.

MUST NOT introduce a pattern merely because its shape can be recognized in the code.

Prefer straightforward functions/modules until a pattern has a concrete payoff.

## 9. Dependencies and supply chain

Before adding a dependency, verify:

- the project does not already provide equivalent functionality;
- the dependency is actively maintained enough for the use case;
- license is compatible;
- security posture is acceptable;
- transitive dependency cost is reasonable;
- versioning and upgrade path are understood.

MUST use the repository's lockfile or equivalent reproducibility mechanism when one exists.

Avoid broad dependency upgrades in unrelated changes.

## 10. Errors, resilience, and external systems

For operations involving networks, filesystems, databases, queues, subprocesses, or third-party APIs:

- use explicit timeouts where appropriate;
- distinguish retryable from non-retryable failures;
- bound retries and use backoff/jitter where applicable;
- make retry-sensitive operations idempotent when practical;
- preserve useful error context;
- fail loudly on corrupted invariants;
- degrade gracefully only when the degraded behavior is intentional and observable.

Do not swallow exceptions/errors without a documented reason.

## 11. Data and migrations

For persistent data changes:

- prefer backward-compatible, staged migrations;
- assume mixed application versions may briefly coexist during deployment when relevant;
- avoid destructive migrations in the same step as code that depends on the new schema unless deployment guarantees make it safe;
- provide rollback or recovery thinking for high-impact changes;
- test migrations against representative data when feasible.

Never rewrite production data assumptions casually.

## 12. Security baseline

MUST:

- validate untrusted input at trust boundaries;
- use parameterized queries or safe APIs instead of string-built commands/queries;
- apply least privilege;
- keep secrets out of logs;
- avoid exposing internal stack traces or sensitive values to untrusted clients;
- preserve authentication, authorization, CSRF, CORS, encryption, and validation controls unless the task explicitly changes them;
- treat deserialization, template rendering, shell execution, path handling, and URL fetching as security-sensitive.

If a change alters a trust boundary, authentication flow, authorization rule, cryptography, or secret handling, explicitly call it out.

## 13. Observability

New production behavior SHOULD be diagnosable.

When appropriate, include:

- structured logs with enough context to correlate failures;
- metrics for throughput, latency, failures, saturation, or queue depth;
- traces across important distributed boundaries;
- health/readiness signals that reflect actual dependency requirements.

Do not log secrets or high-cardinality unbounded data.

## 14. Performance

Do not optimize based on intuition alone.

For performance-sensitive work:

1. identify the relevant workload;
2. measure a baseline;
3. change one important thing at a time;
4. benchmark again;
5. preserve correctness tests.

Prefer algorithmic improvements over micro-optimizations.

## 15. Documentation and comments

Comments should explain **why**, invariants, constraints, failure modes, or non-obvious tradeoffs—not narrate obvious syntax.

Update documentation when behavior, configuration, deployment, APIs, schemas, or operator workflows change.

Examples in documentation should be executable or mechanically checked when practical.

## 16. Git and review hygiene

Prefer commits and diffs that are easy to review.

MUST NOT mix unrelated cleanup into a functional change unless explicitly requested.

Commit messages SHOULD explain intent, not merely restate filenames.

Before declaring work complete, inspect the final diff for:

- accidental generated artifacts;
- debug logging;
- commented-out code;
- secrets;
- unnecessary formatting churn;
- missing tests/docs;
- unrelated changes.

## 17. Completion contract

Before reporting completion:

1. run the most relevant available formatter/linter/type-checker;
2. run focused tests for the changed area;
3. run the broader test suite when feasible and proportionate;
4. inspect the final diff;
5. state what was changed;
6. state what verification was run and its result;
7. state any tests/checks not run and why;
8. state remaining risks, follow-ups, or assumptions.

Never claim a command, test, benchmark, deployment, or verification succeeded unless it was actually run and observed.

## 18. When uncertain

Prefer evidence from, in order:

1. current repository behavior and tests;
2. project documentation and ADRs;
3. upstream official documentation;
4. authoritative standards/specifications;
5. source code;
6. established community practice.

Do not guess about APIs, flags, versions, schemas, or platform behavior when they can be checked.

## 19. External references

These references inform this policy:

- SQLite testing philosophy: https://www.sqlite.org/testing.html
- Google language/style guides: https://google.github.io/styleguide/
- Twelve-Factor App methodology: https://12factor.net/
- CNCF Cloud Native Landscape: https://landscape.cncf.io/

External references evolve. This file is the operational policy. A changed upstream page does not silently rewrite these rules; periodically review and deliberately update this file.

## 20. Project-local overlay template

A project may add a local `AGENTS.md` containing only its differences and specifics:

```md
# Project agent instructions

This repository follows the global engineering policy.

## Commands
- setup:
- test:
- lint:
- format:
- typecheck:
- build:

## Architecture
- ...

## Project-specific constraints
- ...

## Overrides
- ...
```

Keep project-local instructions short, concrete, and executable.