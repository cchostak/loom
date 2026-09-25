# ==============================================================================
# Loom — Enterprise Cloud Development Platform & AI Security Gateway
# ==============================================================================

.PHONY: help init up down restart logs status trace clean check fmt test test-smoke scan doctor lab lab-json setup-isolation up-isolated pipeline pipeline-rag dex-init dex-up dex-down dex-token dex-clean

SHELL := /bin/bash
.DEFAULT_GOAL := help

# ANSI color codes
CYAN   := \033[36m
GREEN  := \033[32m
YELLOW := \033[33m
RED    := \033[31m
BOLD   := \033[1m
NC     := \033[0m

help: ## Display available commands with descriptions
	@echo "=================================================================="
	@echo "  🛠️  Loom — Enterprise Cloud Development & AI Gateway Stack"
	@echo "=================================================================="
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(CYAN)%-16s$(NC) %s\n", $$1, $$2}'

init: ## Initialize directory structure, templates, and environment files
	@echo "==> Initializing Loom environment and directories..."
	@mkdir -p workspace config docker tests docs/adr
	@if [ ! -f .env ]; then \
		echo "Creating .env from .env.example..."; \
		cp .env.example .env; \
		echo "$(YELLOW)⚠️ Please update .env with your OPENROUTER_API_KEY / IDE_PASSWORD.$(NC)"; \
	else \
		echo "$(GREEN)✓ .env already exists.$(NC)"; \
	fi
	@python3 scripts/bootstrap.py
	@echo "$(GREEN)✓ Initialization complete.$(NC)"

up: init ## Build and start all services in detached mode
	@echo "==> Building and launching Loom container stack..."
	docker compose up -d --build --wait --wait-timeout 120
	@echo ""
	@$(MAKE) trace

down: ## Stop and remove all containers and bridge network
	@echo "==> Stopping Loom container stack..."
	docker compose down

restart: down up ## Restart all stack services cleanly

logs: ## Stream unified logs from all services in real time
	docker compose logs -f

status: ## Show runtime status and health of all stack containers
	docker compose ps

trace: ## Display service dashboard endpoints and Jaeger tracing guide
	@echo "================================================================"
	@echo "            🔭 Loom Observability & Service Dashboard           "
	@echo "================================================================"
	@echo " Code-Server (Web IDE):  http://localhost:$$(docker compose port vscode 8080 | awk -F: 'NR == 1 {print $$NF}') (Password in .env)"
	@echo " Jaeger UI (Tracing):    http://localhost:$$(docker compose port jaeger 16686 | awk -F: 'NR == 1 {print $$NF}')"
	@echo " Agentgateway (LLM):     http://localhost:$$(docker compose port control-plane 8080 | awk -F: 'NR == 1 {print $$NF}')/v1"
	@echo " Agentgateway (MCP):     http://localhost:$$(docker compose port control-plane 8080 | awk -F: 'NR == 1 {print $$NF}')"
	@echo " Adversarial Swarm Lab:   make lab"
	@if docker compose ps pipeline 2>/dev/null | grep -q 'running\|Up'; then \
		echo " Pipeline API:           http://localhost:$$(docker compose --profile pipeline port pipeline 8181 | awk -F: 'NR == 1 {print $$NF}')"; \
		echo " Pipeline Docs (OpenAPI):http://localhost:$$(docker compose --profile pipeline port pipeline 8181 | awk -F: 'NR == 1 {print $$NF}')/docs"; \
		echo " Medallion Stats:        http://localhost:$$(docker compose --profile pipeline port pipeline 8181 | awk -F: 'NR == 1 {print $$NF}')/medallion/stats"; \
	fi
	@echo "----------------------------------------------------------------"
	@echo " 🚀 How to inspect OpenTelemetry traces in Jaeger:"
	@echo "   1. Open http://localhost:$$(docker compose port jaeger 16686 | awk -F: 'NR == 1 {print $$NF}') in your browser."
	@echo "   2. Under 'Service', select 'agentgateway'."
	@echo "   3. Click 'Find Traces' to explore live spans, latencies, and tool calls."
	@echo "================================================================"

check: ## Run static linters and checks across Go, Shell, and Config files
	@echo "==> [1/4] Checking Go formatting and vet..."
	@cd docker && test -z "$$(gofmt -l .)" || (echo -e "$(RED)Unformatted Go files found:$(NC)" && gofmt -l . && exit 1)
	@cd docker && go vet ./...
	@echo -e "$(GREEN)✓ Go formatting and vet passed.$(NC)"
	@echo "==> [2/4] Validating Docker Compose configuration..."
	@if [ ! -f .env ]; then cp .env.example .env; fi
	@docker compose config -q
	@docker run --rm -e OPENROUTER_API_KEY=validation-only \
		-v "$$(pwd)/config/agentgateway-config.yaml:/config.yaml:ro" \
		ghcr.io/agentgateway/agentgateway:v1.5.0 -f /config.yaml --validate-only
	@echo -e "$(GREEN)✓ Docker Compose configuration is valid.$(NC)"
	@echo "==> [3/4] Validating Shell script syntax..."
	@bash -n tests/smoke_test.sh tests/run_all.sh
	@echo -e "$(GREEN)✓ Shell scripts passed syntax validation.$(NC)"
	@echo "==> [4/4] Checking YAML and Markdown formatting..."
	@if command -v yamllint >/dev/null 2>&1; then \
		yamllint -d '{extends: relaxed, rules: {line-length: {max: 180}}}' . && echo -e "$(GREEN)✓ yamllint passed.$(NC)"; \
	else \
		echo -e "$(YELLOW)ℹ yamllint not installed locally (skipped).$(NC)"; \
	fi
	@echo -e "$(BOLD)$(GREEN)✓ All static checks passed.$(NC)"

fmt: ## Auto-format Go code and repository files
	@echo "==> Formatting Go source files..."
	@cd docker && gofmt -w -s .
	@echo -e "$(GREEN)✓ Go source files formatted.$(NC)"

test: ## Execute Go unit tests with race detection and coverage reporting
	@echo "==> Running unit tests and policy verification..."
	@cd docker && go test -v -race -coverprofile=coverage.out ./...
	@echo "==> Code Coverage Summary:"
	@cd docker && go tool cover -func=coverage.out | tail -n 1
	@echo -e "$(GREEN)✓ Unit tests completed successfully.$(NC)"

test-smoke: ## Execute end-to-end integration smoke test harness against containers
	@echo "==> Executing integration smoke test suite..."
	@chmod +x tests/smoke_test.sh
	@./tests/smoke_test.sh

lab: init ## Run the keyless adversarial agent-swarm security lab
	@echo "==> Starting the Loom guardrail and adversarial swarm lab..."
	docker compose up -d --build --wait --wait-timeout 60 guardrail-proxy
	docker compose --profile lab build swarm-lab
	docker compose --profile lab run --rm swarm-lab

lab-json: init ## Run the swarm lab and emit a machine-readable JSON report
	@docker compose up -d --build --wait --wait-timeout 60 guardrail-proxy
	@docker compose --profile lab build swarm-lab > /dev/null
	@docker compose --profile lab run --rm swarm-lab --json

setup-isolation: ## Install gVisor (runsc) and register it with the Docker daemon
	@echo "==> Setting up container isolation runtimes..."
	@echo "$(YELLOW)⚠  This step requires sudo and will modify /etc/docker/daemon.json.$(NC)"
	@echo "$(YELLOW)   Append --with-kata to also install Kata Containers (requires KVM).$(NC)"
	sudo bash docker/setup-isolation.sh $(ISOLATION_FLAGS)
	@echo -e "$(GREEN)✓ Isolation setup complete. Run 'make up-isolated' to start the sandboxed stack.$(NC)"

up-isolated: init ## Start the stack with gVisor container isolation (run make setup-isolation first)
	@echo "==> Launching Loom stack with gVisor (runsc) isolation..."
	@if ! docker info --format '{{range $$k, $$v := .Runtimes}}{{$$k}} {{end}}' 2>/dev/null | grep -q runsc; then \
		echo -e "$(RED)✗ runsc runtime is not registered with Docker.$(NC)"; \
		echo "  Run: make setup-isolation"; \
		exit 1; \
	fi
	docker compose -f docker-compose.yml -f docker-compose.isolation.yml up -d --build --wait --wait-timeout 120
	@echo ""
	@$(MAKE) trace
	@echo -e "$(CYAN)  Isolation mode:$(NC) control-plane, guardrail-proxy, presidio-analyzer, agentgateway → runsc (gVisor)"
	@echo -e "$(CYAN)  Verify:$(NC) docker inspect guardrail-proxy --format '{{.HostConfig.Runtime}}'"

pipeline: init ## Build and start the ingestion pipeline (medallion + RAG) and ingest sample data
	@echo "==> Launching ingestion pipeline stack (Bronze → Silver → Gold → RAG)..."
	docker compose --profile pipeline up -d --build --wait --wait-timeout 180
	@echo ""
	@echo "==> Ingesting sample documents into the medallion pipeline..."
	python3 pipeline/ingest_sample.py --wait
	@echo ""
	@$(MAKE) trace

pipeline-rag: ## Run a demo RAG query against the ingested sample data
	@echo "==> Running demo RAG query..."
	@curl -sf -X POST http://localhost:$$(docker compose port pipeline 8181 2>/dev/null | awk -F: 'NR==1{print $$NF}' || echo 8181)/rag \
		-H 'Content-Type: application/json' \
		-d '{"query": "How does the guardrail proxy protect LLM responses?", "k": 4}' \
		| python3 -m json.tool || echo "Pipeline service not running — run: make pipeline"

scan: ## Enforce dependency, secret and core-image vulnerability gates (requires Trivy)
	@command -v trivy >/dev/null || { echo "Install Trivy before running make scan."; exit 1; }
	trivy fs --cache-dir .loom/trivy-cache --scanners vuln,secret --severity HIGH,CRITICAL --exit-code 1 \
		--skip-dirs .loom --skip-dirs .git --skip-files .env .
	@for image in loom-control-plane loom-guardrail-proxy loom-agentgateway; do \
		trivy image --cache-dir .loom/trivy-cache --scanners vuln --severity HIGH,CRITICAL --exit-code 1 "$$image" || exit $$?; \
	done

doctor: ## Validate prerequisite CLI tools, Docker daemon, network ports, and .env
	@echo "================================================================"
	@echo "             🩺 Loom System & Environment Doctor                "
	@echo "================================================================"
	@for tool in docker git make curl go; do \
		if command -v $$tool >/dev/null 2>&1; then \
			echo -e "   $(GREEN)✓ $$tool$$(echo '                ' | cut -c 1-$$(expr 15 - $${#tool})) : $$(command -v $$tool)$(NC)"; \
		else \
			echo -e "   $(RED)✗ $$tool$$(echo '                ' | cut -c 1-$$(expr 15 - $${#tool})) : NOT FOUND$(NC)"; \
		fi \
	done
	@if docker info >/dev/null 2>&1; then echo -e "   $(GREEN)✓ Docker daemon is running and responsive.$(NC)"; \
	else echo -e "   $(RED)✗ Docker daemon is unreachable.$(NC)"; fi
	@for cfg in .env config/agentgateway-config.yaml config/otel-collector-config.yaml; do \
		if [ -f $$cfg ]; then echo -e "   $(GREEN)✓ $$cfg exists.$(NC)"; \
		else echo -e "   $(YELLOW)⚠ $$cfg missing.$(NC)"; fi; \
	done
	@for port in 8080 8443 16686 3000; do \
		if command -v nc >/dev/null 2>&1 && nc -z 127.0.0.1 $$port >/dev/null 2>&1; then \
			echo -e "   $(YELLOW)⚠ Port $$port in use (stack may be running).$(NC)"; \
		fi \
	done
	@RUNTIMES=$$(docker info --format '{{range $$k, $$v := .Runtimes}}{{$$k}} {{end}}' 2>/dev/null || echo ''); \
	for rt in runsc kata; do \
		if echo "$$RUNTIMES" | grep -q "$$rt"; then echo -e "   $(GREEN)✓ $$rt runtime registered$(NC)"; \
		else echo -e "   $(YELLOW)⚠ $$rt runtime not installed (optional, run 'make setup-isolation')$(NC)"; fi; \
	done
	@echo "================================================================"

clean: down ## Stop containers and clean build artifacts; retain audit/data volumes
	@echo "==> Cleaning test artifacts; audit and data volumes are retained."
	@rm -f docker/coverage.out docker/coverage.html docker/guardrail
	@echo "$(GREEN)✓ Cleanup complete.$(NC)"

UV ?= $(shell command -v uv 2>/dev/null || ( [ -x $(CURDIR)/.loom/tooling/bin/uv ] && echo $(CURDIR)/.loom/tooling/bin/uv ) || echo uv)

.PHONY: strands strands-test strands-lab mcp-init mcp-test test-telemetry test-all
mcp-init: ## Bootstrap MCP tool contract schemas and Ed25519 signing keys
	@python3 scripts/bootstrap_mcp.py

mcp-test: ## Run strict MCP schema validation and tool poisoning test suite
	$(UV) run --locked --project integrations/strands pytest -q integrations/strands/tests/test_mcp*.py

test-telemetry: ## Verify guardrail event normalization to BlackShield finding schema
	@cd docker && go test -v -race -run 'Telemetry' ./enterprise

test-all: test strands-test mcp-test test-telemetry ## Run complete test suite across Go and Python
	@echo -e "$(BOLD)$(GREEN)✓ All Loom Go and Python test suites passed.$(NC)"

strands: init ## Run isolated Strands roles through Loom (requires provider API key)
	$(UV) run --locked --project integrations/strands python integrations/strands/runner.py demo

strands-test: ## Validate the locked Strands package and run keyless unit tests
	$(UV) lock --check --project integrations/strands
	$(UV) run --locked --project integrations/strands ruff check integrations/strands scripts/bootstrap_strands.py
	$(UV) run --locked --project integrations/strands pytest -q integrations/strands/tests

strands-lab: init ## Run real Strands, MCP and policy against an isolated keyless provider fixture
	$(UV) run --locked --project integrations/strands python integrations/strands/runner.py lab

# ==============================================================================
# Dex OIDC identity stage (Stage 1 security roadmap)
# ==============================================================================

dex-init: init ## Generate Dex client secrets and OIDC config (writes config/dex.yaml + config/oidc.json)
	@echo "==> Generating Dex client credentials..."
	@python3 scripts/bootstrap_dex.py
	@echo "$(GREEN)✓ Dex secrets ready in .loom/dex/ and config/oidc.json$(NC)"

dex-up: dex-init ## Build and start the full stack with Dex OIDC (overlay)
	@echo "==> Starting Loom + Dex stack..."
	docker compose -f docker-compose.yml -f docker-compose.dex.yml up -d --build --wait --wait-timeout 180
	@echo ""
	@echo "$(CYAN)Dex OIDC endpoint: http://127.0.0.1:$${LOOM_DEX_PORT:-5556}/dex$(NC)"
	@$(MAKE) trace

dex-down: ## Stop the Loom + Dex stack
	@echo "==> Stopping Loom + Dex stack..."
	docker compose -f docker-compose.yml -f docker-compose.dex.yml down

dex-token: ## Fetch a test access token from Dex for the loom-ide workload (requires curl + jq)
	@echo "==> Fetching test access token from Dex..."
	@[ -f .loom/dex/loom-ide.secret ] || (echo "$(RED)Run 'make dex-init' first$(NC)" && exit 1)
	@SECRET=$$(cat .loom/dex/loom-ide.secret); \
	curl -sf \
	  -d "grant_type=client_credentials" \
	  -d "client_id=loom-ide" \
	  --data-urlencode "client_secret=$${SECRET}" \
	  -d "scope=model:invoke workspace:read" \
	  http://127.0.0.1:$${LOOM_DEX_PORT:-5556}/dex/token \
	| jq -r '.access_token'

dex-clean: dex-down ## Remove Dex secrets and generated OIDC config (idempotent)
	@echo "==> Cleaning Dex state..."
	@rm -rf .loom/dex
	@git checkout -- config/dex.yaml 2>/dev/null || true
	@rm -f config/oidc.json
	@docker volume rm loom_dex-data 2>/dev/null || true
	@echo "$(GREEN)✓ Dex state cleared.$(NC)"
