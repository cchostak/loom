#!/usr/bin/env bash
# ==============================================================================
# Loom Unified Test Runner - Unit, Policy & Static Verification
# ==============================================================================
set -euo pipefail

BOLD='\033[1m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "\n${BOLD}${CYAN}==> [1/3] Running Go Unit & Policy Tests...${NC}"
cd docker
go test -v -race -coverprofile=coverage.out ./...
go tool cover -func=coverage.out | tail -n 1
go vet ./...
cd ..
python3 -m unittest discover -s tests -p "test_*.py"

echo -e "\n${BOLD}${CYAN}==> [2/3] Validating Configuration & Manifests...${NC}"
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  if [ ! -f .env ]; then
    cp .env.example .env
  fi
  docker compose config -q
  echo -e "${GREEN}✓ Docker Compose configuration is valid.${NC}"
fi

echo -e "\n${BOLD}${CYAN}==> [3/3] Checking Shell Script POSIX Compliance...${NC}"
bash -n tests/smoke_test.sh
bash -n tests/run_all.sh
echo -e "${GREEN}✓ Shell scripts passed syntax validation.${NC}"

echo -e "\n${BOLD}${GREEN}✓ All local test suites passed successfully.${NC}\n"
