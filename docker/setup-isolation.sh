#!/usr/bin/env bash
# ==============================================================================
# Loom — Container Isolation Setup
# ==============================================================================
# Installs gVisor (runsc) and optionally Kata Containers on the host, then
# registers both runtimes with the Docker daemon. The script is idempotent:
# running it a second time is safe.
#
# Usage:
#   sudo bash docker/setup-isolation.sh [--with-kata] [--dry-run]
#
# Options:
#   --with-kata   Also install Kata Containers (requires KVM).
#   --dry-run     Print what would be done without making any changes.
#
# After running this script, bring up the stack with deep isolation:
#   make up-isolated
# ==============================================================================

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log_info()    { echo -e "${CYAN}ℹ [INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}✓ [OK]${NC}   $*"; }
log_warn()    { echo -e "${YELLOW}⚠ [WARN]${NC} $*"; }
log_fail()    { echo -e "${RED}✗ [FAIL]${NC} $*"; }
log_step()    { echo -e "\n${BOLD}${CYAN}==> $*${NC}"; }

# ── Argument parsing ──────────────────────────────────────────────────────────
WITH_KATA=false
DRY_RUN=false

for arg in "$@"; do
  case "$arg" in
    --with-kata) WITH_KATA=true ;;
    --dry-run)   DRY_RUN=true ;;
    *)
      log_fail "Unknown argument: $arg"
      echo "Usage: sudo bash docker/setup-isolation.sh [--with-kata] [--dry-run]"
      exit 1
      ;;
  esac
done

# ── Root check ────────────────────────────────────────────────────────────────
if [[ "$EUID" -ne 0 ]] && [[ "$DRY_RUN" == "false" ]]; then
  log_fail "This script must be run as root (use sudo)."
  exit 1
fi

run() {
  if [[ "$DRY_RUN" == "true" ]]; then
    echo -e "  ${YELLOW}[dry-run]${NC} $*"
  else
    "$@"
  fi
}

# ── Prerequisites ─────────────────────────────────────────────────────────────
log_step "Checking prerequisites"

MISSING_DEPS=()
for dep in curl apt-get jq docker; do
  command -v "$dep" > /dev/null 2>&1 || MISSING_DEPS+=("$dep")
done

if [[ ${#MISSING_DEPS[@]} -gt 0 ]]; then
  log_fail "Missing required tools: ${MISSING_DEPS[*]}"
  exit 1
fi
log_success "All required tools present"

if ! docker info > /dev/null 2>&1; then
  log_fail "Docker daemon is not running. Please start Docker Engine first."
  exit 1
fi
log_success "Docker daemon is running"

# ── KVM check (required for Kata) ─────────────────────────────────────────────
KVM_AVAILABLE=false
if [[ -e /dev/kvm ]]; then
  KVM_AVAILABLE=true
  log_success "KVM is available (/dev/kvm found)"
else
  log_warn "KVM not found — Kata Containers will not be available."
  if [[ "$WITH_KATA" == "true" ]]; then
    log_fail "--with-kata requested but KVM is not available. Aborting."
    exit 1
  fi
fi

# ── Install gVisor ────────────────────────────────────────────────────────────
log_step "Installing gVisor (runsc)"

GVISOR_URL="https://storage.googleapis.com/gvisor/releases/release/latest/$(uname -m)"

if command -v runsc > /dev/null 2>&1 && runsc --version > /dev/null 2>&1; then
  log_success "runsc already installed: $(runsc --version 2>&1 | head -1)"
else
  log_info "Downloading gVisor runsc binary..."
  run curl -fsSL "${GVISOR_URL}/runsc"     -o /tmp/runsc
  run curl -fsSL "${GVISOR_URL}/runsc.sha512" -o /tmp/runsc.sha512

  log_info "Verifying SHA-512 checksum..."
  if [[ "$DRY_RUN" == "false" ]]; then
    (cd /tmp && sha512sum -c runsc.sha512)
  else
    echo -e "  ${YELLOW}[dry-run]${NC} sha512sum -c /tmp/runsc.sha512"
  fi

  run install -o root -g root -m 755 /tmp/runsc /usr/local/bin/runsc
  run rm -f /tmp/runsc /tmp/runsc.sha512
  log_success "gVisor runsc installed to /usr/local/bin/runsc"
fi

# ── Install Kata Containers (optional) ───────────────────────────────────────
if [[ "$WITH_KATA" == "true" ]] && [[ "$KVM_AVAILABLE" == "true" ]]; then
  log_step "Installing Kata Containers"

  if command -v kata-runtime > /dev/null 2>&1 || command -v containerd-shim-kata-v2 > /dev/null 2>&1; then
    log_success "Kata Containers already installed"
  else
    log_info "Adding Kata Containers APT repository..."
    run bash -c 'apt-get install -y software-properties-common'
    run bash -c 'add-apt-repository -y ppa:kata-containers/ppa'
    run apt-get update -q
    run apt-get install -y kata-containers
    log_success "Kata Containers installed"
  fi
fi

# ── Compatibility check: gVisor + Presidio ────────────────────────────────────
log_step "Verifying gVisor compatibility with Presidio image"

if [[ "$DRY_RUN" == "true" ]]; then
  log_info "[dry-run] Would run: docker run --runtime=runsc --rm mcr.microsoft.com/presidio-analyzer:latest python -c 'print(\"gvisor ok\")'"
else
  log_info "Pulling Presidio analyzer image for compat test (this may take a moment)..."
  COMPAT_OUT=$(docker run --runtime=runsc --rm \
    mcr.microsoft.com/presidio-analyzer:latest \
    python -c 'import flask; print("gvisor-compat-ok")' 2>&1) || true

  if echo "$COMPAT_OUT" | grep -q "gvisor-compat-ok"; then
    log_success "Presidio analyzer is compatible with gVisor (runsc)"
  else
    log_warn "gVisor compat test produced unexpected output — review before using isolation:"
    echo "$COMPAT_OUT" | head -20
    log_warn "The overlay file has been created but manually verify before deploying."
  fi
fi

# ── Patch /etc/docker/daemon.json ─────────────────────────────────────────────
log_step "Registering runtimes with Docker daemon"

DAEMON_JSON="/etc/docker/daemon.json"
BACKUP_JSON="${DAEMON_JSON}.loom-backup.$(date +%Y%m%d%H%M%S)"

if [[ "$DRY_RUN" == "false" ]]; then
  # Back up existing daemon.json
  if [[ -f "$DAEMON_JSON" ]]; then
    cp "$DAEMON_JSON" "$BACKUP_JSON"
    log_info "Backed up existing daemon.json → $BACKUP_JSON"
    EXISTING=$(cat "$DAEMON_JSON")
  else
    EXISTING="{}"
    mkdir -p /etc/docker
  fi

  # Merge in the runtime entries using jq
  RUNTIMES_PATCH='{
    "runtimes": {
      "runsc": {
        "path": "/usr/local/bin/runsc",
        "runtimeArgs": ["--network=sandbox", "--platform=systrap"]
      },
      "runsc-kvm": {
        "path": "/usr/local/bin/runsc",
        "runtimeArgs": ["--network=sandbox", "--platform=kvm"]
      }
    }
  }'

  if [[ "$WITH_KATA" == "true" ]] && [[ "$KVM_AVAILABLE" == "true" ]]; then
    RUNTIMES_PATCH=$(echo "$RUNTIMES_PATCH" | jq '.runtimes["io.containerd.kata.v2"] = {
      "path": "/usr/bin/containerd-shim-kata-v2",
      "runtimeType": "io.containerd.kata.v2"
    }')
  fi

  MERGED=$(echo "$EXISTING" | jq --argjson patch "$RUNTIMES_PATCH" '. * $patch')
  echo "$MERGED" | tee "$DAEMON_JSON" > /dev/null
  log_success "daemon.json updated with gVisor runtime entries"

  log_info "Reloading Docker daemon to pick up new runtimes..."
  systemctl reload docker || (service docker restart && log_warn "Used service restart (systemctl reload failed)")
  sleep 2

  # Verify registration
  REGISTERED=$(docker info --format '{{range $k, $v := .Runtimes}}{{$k}} {{end}}')
  if echo "$REGISTERED" | grep -q "runsc"; then
    log_success "runsc runtime is registered with Docker"
  else
    log_fail "runsc not found in 'docker info' after daemon reload. Check /etc/docker/daemon.json manually."
    exit 1
  fi
else
  log_info "[dry-run] Would merge runtime entries into $DAEMON_JSON and reload Docker"
  cat << 'EOF'
  Runtimes to be added:
    runsc        → /usr/local/bin/runsc --network=sandbox --platform=systrap
    runsc-kvm    → /usr/local/bin/runsc --network=sandbox --platform=kvm
EOF
fi

# ── Final summary ─────────────────────────────────────────────────────────────
echo ""
echo "================================================================"
echo -e "${BOLD}${GREEN}✓ Isolation setup complete${NC}"
echo "================================================================"
echo ""
echo "  Registered runtimes:"
echo "    runsc      — gVisor (systrap platform, userspace kernel)"
echo "    runsc-kvm  — gVisor (KVM platform, faster I/O when KVM is available)"
if [[ "$WITH_KATA" == "true" ]]; then
  echo "    kata       — Kata Containers (QEMU/KVM microVM)"
fi
echo ""
echo "  Next steps:"
echo "    make up-isolated       # Start the stack with gVisor isolation"
echo "    make doctor            # Verify runtimes are detected"
echo ""
echo "  To revert daemon.json:"
if [[ "$DRY_RUN" == "false" ]] && [[ -f "$BACKUP_JSON" ]]; then
  echo "    sudo cp $BACKUP_JSON $DAEMON_JSON && sudo systemctl reload docker"
else
  echo "    sudo cp <backup> /etc/docker/daemon.json && sudo systemctl reload docker"
fi
echo "================================================================"
