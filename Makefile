# ==============================================================================
# Loom — Enterprise Cloud Development Platform & AI Security Gateway
# ==============================================================================

.PHONY: help init up down restart logs status trace clean check fmt test test-smoke scan doctor lab lab-json

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
	@echo " Agentgateway (LLM):     http://localhost:$$(docker compose port agentgateway 8080 | awk -F: 'NR == 1 {print $$NF}')/v1"
	@echo " Agentgateway (MCP):     http://localhost:$$(docker compose port agentgateway 3000 | awk -F: 'NR == 1 {print $$NF}')"
	@echo " Guardrail Proxy Health: http://localhost:$$(docker compose port guardrail-proxy 9090 | awk -F: 'NR == 1 {print $$NF}')/health"
	@echo " Adversarial Swarm Lab:   make lab"
	@echo " OTel Collector (gRPC):  localhost:$$(docker compose port otel-collector 4317 | awk -F: 'NR == 1 {print $$NF}')"
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
	@docker compose --profile lab build swarm-lab >/dev/null
	@docker compose --profile lab run --rm swarm-lab --json

scan: ## Run local secret and vulnerability audits
	@echo "==> Checking for accidental secret leaks..."
	@if command -v gitleaks >/dev/null 2>&1; then \
		gitleaks detect --no-git -v; \
	elif docker run --rm -v "$$(pwd):/path" zricethezav/gitleaks:latest detect --source="/path" --verbose --no-git 2>/dev/null; then \
		echo -e "$(GREEN)✓ Gitleaks container scan passed.$(NC)"; \
	else \
		echo -e "$(YELLOW)ℹ Gitleaks not installed; checking for obvious key leaks...$(NC)"; \
		grep -rnE 'sk-or-v1-[a-zA-Z0-9]{30,}' . --exclude=.env.example --exclude=.env || echo -e "$(GREEN)✓ No raw API keys detected.$(NC)"; \
	fi

doctor: ## Validate prerequisite CLI tools, Docker daemon, network ports, and .env
	@echo "================================================================"
	@echo "             🩺 Loom System & Environment Doctor                "
	@echo "================================================================"
	@echo "1. Checking Required CLI Utilities:"
	@for tool in docker git make curl go; do \
		if command -v $$tool >/dev/null 2>&1; then \
			echo -e "   $(GREEN)✓ $$tool$$(echo '                ' | cut -c 1-$$(expr 15 - $${#tool})) : $$(command -v $$tool)$(NC)"; \
		else \
			echo -e "   $(RED)✗ $$tool$$(echo '                ' | cut -c 1-$$(expr 15 - $${#tool})) : NOT FOUND$(NC)"; \
		fi \
	done
	@echo ""
	@echo "2. Checking Docker Daemon Status:"
	@if docker info >/dev/null 2>&1; then \
		echo -e "   $(GREEN)✓ Docker daemon is running and responsive.$(NC)"; \
	else \
		echo -e "   $(RED)✗ Docker daemon is unreachable. Please start Docker Engine.$(NC)"; \
	fi
	@echo ""
	@echo "3. Checking Configuration Files:"
	@if [ -f .env ]; then \
		echo -e "   $(GREEN)✓ .env file exists.$(NC)"; \
	else \
		echo -e "   $(YELLOW)⚠ .env missing. Run 'make init' to create it.$(NC)"; \
	fi
	@if [ -f config/agentgateway-config.yaml ]; then \
		echo -e "   $(GREEN)✓ config/agentgateway-config.yaml exists.$(NC)"; \
	else \
		echo -e "   $(RED)✗ config/agentgateway-config.yaml is missing.$(NC)"; \
	fi
	@if [ -f config/otel-collector-config.yaml ]; then \
		echo -e "   $(GREEN)✓ config/otel-collector-config.yaml exists.$(NC)"; \
	else \
		echo -e "   $(RED)✗ config/otel-collector-config.yaml is missing.$(NC)"; \
	fi
	@echo ""
	@echo "4. Checking Port Availability (8080, 8443, 9090, 16686, 4317, 3000):"
	@for port in 8080 8443 9090 16686 4317 3000; do \
		if command -v nc >/dev/null 2>&1; then \
			if nc -z 127.0.0.1 $$port >/dev/null 2>&1; then \
				echo -e "   $(YELLOW)⚠ Port $$port is currently in use (possibly by running Loom stack).$(NC)"; \
			else \
				echo -e "   $(GREEN)✓ Port $$port is free.$(NC)"; \
			fi \
		fi \
	done
	@echo "================================================================"
	@echo -e "$(BOLD)$(GREEN)✓ Doctor diagnostic check finished.$(NC)"

clean: down ## Stop containers, remove volumes, and clean coverage/binary artifacts
	@echo "==> Cleaning container volumes and test artifacts..."
	docker compose down -v 2>/dev/null || true
	@rm -f docker/coverage.out docker/coverage.html docker/guardrail
	@echo "$(GREEN)✓ Cleanup complete.$(NC)"
