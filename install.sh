#!/usr/bin/env bash
set -euo pipefail

## ==============================================================================
# ADE NVIDIA OpenShell Plugin Installer: agy-box, codex-box & claude-box
# ==============================================================================
# This script sets up fully isolated, Landlock-sandboxed runners for:
#   1. Google Antigravity CLI (agy-box)
#   2. OpenAI Codex CLI (codex-box)
#   3. Anthropic Claude Code CLI (claude-box)
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_INSTALL_DIR="${HOME}/.local/bin"
POLICIES_DIR="${HOME}/.agents/policies"
ORCA_POLICIES_DIR="${HOME}/.agents/orca-openshell-policies"
FORCE_REBUILD=false

for arg in "$@"; do
  case "$arg" in
    --rebuild|-r)
      FORCE_REBUILD=true
      shift
      ;;
    --help|-h)
      echo "Usage: $0 [OPTIONS]"
      echo ""
      echo "Options:"
      echo "  -r, --rebuild    Force rebuilding docker container images"
      echo "  -h, --help       Show this help message"
      exit 0
      ;;
  esac
done

echo "========================================================================"
echo "  ADE NVIDIA OpenShell Plugin Installer (agy-box, codex-box & claude-box)"
echo "========================================================================"
echo ""

# 1. Dependency checks
echo "==> [1/6] Checking host prerequisites..."

if ! command -v docker >/dev/null 2>&1; then
  echo "Error: 'docker' is not installed or not in PATH."
  echo "Please install Docker Desktop or OrbStack and start the daemon."
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "Error: Docker daemon is not running."
  echo "Please start Docker and rerun this installer."
  exit 1
fi
echo "  ✓ Docker daemon is active"

if ! command -v openshell >/dev/null 2>&1; then
  echo "Error: 'openshell' CLI is not installed."
  echo "Please install OpenShell (e.g., pip install openshell or native package)."
  exit 1
fi
echo "  ✓ OpenShell CLI found: $(openshell --version 2>&1 | head -n 1)"

if ! command -v python3 >/dev/null 2>&1; then
  echo "Error: 'python3' is required to run sandbox bridges."
  exit 1
fi
echo "  ✓ Python3 found: $(python3 --version)"

if ! command -v yq >/dev/null 2>&1; then
  echo "  ! Note: 'yq' is recommended for YAML policy parsing."
else
  echo "  ✓ yq found: $(yq --version 2>&1 | head -n 1)"
fi

# 2. Build Docker Images
echo ""
echo "==> [2/6] Building sandbox Docker images..."

# Build openshell-base:latest
if [[ "$FORCE_REBUILD" == true ]] || ! docker image inspect openshell-base:latest >/dev/null 2>&1; then
  echo "  -> Building openshell-base:latest (development toolchain: Go, Python, Node, Make, utilities)..."
  docker build \
    -t openshell-base:latest \
    -f "${SCRIPT_DIR}/docker/Dockerfile.base" \
    "${SCRIPT_DIR}/docker"
  echo "  ✓ openshell-base:latest ready"
else
  echo "  ✓ openshell-base:latest already present (use --rebuild to recreate)"
fi

# Build openshell-codex:latest
if [[ "$FORCE_REBUILD" == true ]] || ! docker image inspect openshell-codex:latest >/dev/null 2>&1; then
  echo "  -> Building openshell-codex:latest..."
  docker build \
    -t openshell-codex:latest \
    -f "${SCRIPT_DIR}/docker/Dockerfile.codex" \
    "${SCRIPT_DIR}/docker"
  echo "  ✓ openshell-codex:latest ready"
else
  echo "  ✓ openshell-codex:latest already present (use --rebuild to recreate)"
fi

# Build openshell-antigravity:latest
if [[ "$FORCE_REBUILD" == true ]] || ! docker image inspect openshell-antigravity:latest >/dev/null 2>&1; then
  echo "  -> Building openshell-antigravity:latest..."
  docker build \
    -t openshell-antigravity:latest \
    -f "${SCRIPT_DIR}/docker/Dockerfile.antigravity" \
    "${SCRIPT_DIR}/docker"
  echo "  ✓ openshell-antigravity:latest ready"
else
  echo "  ✓ openshell-antigravity:latest already present (use --rebuild to recreate)"
fi

# Build openshell-claude:latest
if [[ "$FORCE_REBUILD" == true ]] || ! docker image inspect openshell-claude:latest >/dev/null 2>&1; then
  echo "  -> Building openshell-claude:latest..."
  docker build \
    -t openshell-claude:latest \
    -f "${SCRIPT_DIR}/docker/Dockerfile.claude" \
    "${SCRIPT_DIR}/docker"
  echo "  ✓ openshell-claude:latest ready"
else
  echo "  ✓ openshell-claude:latest already present (use --rebuild to recreate)"
fi

# 3. Configure OpenShell Profiles & Providers
echo ""
echo "==> [3/6] Configuring OpenShell provider profiles & providers..."

# Antigravity Profile
if openshell profile list --type provider 2>/dev/null | grep -q "antigravity"; then
  openshell profile update -f "${SCRIPT_DIR}/profiles/antigravity.profile.yaml" >/dev/null 2>&1 || true
  echo "  ✓ Profile 'antigravity' up to date"
else
  openshell profile import -f "${SCRIPT_DIR}/profiles/antigravity.profile.yaml" >/dev/null 2>&1 || true
  echo "  ✓ Profile 'antigravity' imported"
fi

# Codex Profile
if openshell profile list --type provider 2>/dev/null | grep -q "codex"; then
  openshell profile update -f "${SCRIPT_DIR}/profiles/codex.profile.yaml" >/dev/null 2>&1 || true
  echo "  ✓ Profile 'codex' up to date"
else
  openshell profile import -f "${SCRIPT_DIR}/profiles/codex.profile.yaml" >/dev/null 2>&1 || true
  echo "  ✓ Profile 'codex' imported"
fi

# Claude Profile
if openshell profile list --type provider 2>/dev/null | grep -q "claude-code"; then
  openshell profile update -f "${SCRIPT_DIR}/profiles/claude-code.profile.yaml" >/dev/null 2>&1 || true
  echo "  ✓ Profile 'claude-code' up to date"
else
  openshell profile import -f "${SCRIPT_DIR}/profiles/claude-code.profile.yaml" >/dev/null 2>&1 || true
  echo "  ✓ Profile 'claude-code' imported"
fi

# Antigravity Provider
if ! openshell provider list 2>/dev/null | grep -q "antigravity"; then
  openshell provider create --name antigravity --type antigravity >/dev/null 2>&1 || true
  echo "  ✓ Provider 'antigravity' created"
else
  echo "  ✓ Provider 'antigravity' exists"
fi

# Codex Provider
if ! openshell provider list 2>/dev/null | grep -q "codex"; then
  openshell provider create --name codex --type codex >/dev/null 2>&1 || true
  echo "  ✓ Provider 'codex' created"
else
  echo "  ✓ Provider 'codex' exists"
fi

# Claude Provider
if ! openshell provider list 2>/dev/null | grep -q "claude-code"; then
  openshell provider create --name claude-code --type claude-code >/dev/null 2>&1 || true
  echo "  ✓ Provider 'claude-code' created"
else
  echo "  ✓ Provider 'claude-code' exists"
fi

# GitHub Provider
if ! openshell provider list 2>/dev/null | grep -q "github"; then
  openshell provider create --name github --type github >/dev/null 2>&1 || true
  echo "  ✓ Provider 'github' created"
else
  echo "  ✓ Provider 'github' exists"
fi

# 4. Install Global Security Policies
echo ""
echo "==> [4/6] Installing security policies to ~/.agents/policies/......"
mkdir -p "${POLICIES_DIR}"
cp -f "${SCRIPT_DIR}/policies/default.yaml" "${POLICIES_DIR}/default.yaml"
cp -f "${SCRIPT_DIR}/policies/antigravity.yaml" "${POLICIES_DIR}/antigravity.yaml"
cp -f "${SCRIPT_DIR}/policies/claude.yaml" "${POLICIES_DIR}/claude.yaml"
mkdir -p "${ORCA_POLICIES_DIR}"
cp -f "${SCRIPT_DIR}/policies/orca-codex.json" "${ORCA_POLICIES_DIR}/codex.json"
cp -f "${SCRIPT_DIR}/policies/orca-claude.json" "${ORCA_POLICIES_DIR}/claude.json"
echo "  ✓ Installed default.yaml, antigravity.yaml, and claude.yaml to ${POLICIES_DIR}"

# 5. Build & Install TypeScript Bridge to ~/.local/bin
echo ""
echo "==> [5/6] Building & installing TypeScript bridge executables to ${BIN_INSTALL_DIR}..."
mkdir -p "${BIN_INSTALL_DIR}"

if [[ -d "${SCRIPT_DIR}/ts" ]]; then
  echo "  -> Building @orca/openshell-bridge TypeScript bundle..."
  (cd "${SCRIPT_DIR}/ts" && bun run bundle >/dev/null 2>&1 || (npm install --silent >/dev/null 2>&1 && npm run build >/dev/null 2>&1))
  cp -f "${SCRIPT_DIR}/ts/dist/agent-box.bundle.js" "${BIN_INSTALL_DIR}/agent-box"
  chmod +x "${BIN_INSTALL_DIR}/agent-box"

  ln -sf "${BIN_INSTALL_DIR}/agent-box" "${BIN_INSTALL_DIR}/agy-box"
  ln -sf "${BIN_INSTALL_DIR}/agent-box" "${BIN_INSTALL_DIR}/codex-box"
  ln -sf "${BIN_INSTALL_DIR}/agent-box" "${BIN_INSTALL_DIR}/claude-box"
  echo "  ✓ Compiled and linked agent-box, agy-box, codex-box, and claude-box (TypeScript)"
fi

# Also preserve Python reference bridges as fallback
cp -f "${SCRIPT_DIR}/bin/agy-openshell-bridge.py" "${BIN_INSTALL_DIR}/agy-openshell-bridge.py"
cp -f "${SCRIPT_DIR}/bin/codex-openshell-bridge.py" "${BIN_INSTALL_DIR}/codex-openshell-bridge.py"
cp -f "${SCRIPT_DIR}/bin/claude-openshell-bridge.py" "${BIN_INSTALL_DIR}/claude-openshell-bridge.py"
chmod +x \
  "${BIN_INSTALL_DIR}/agy-openshell-bridge.py" \
  "${BIN_INSTALL_DIR}/codex-openshell-bridge.py" \
  "${BIN_INSTALL_DIR}/claude-openshell-bridge.py"

# 6. Verify and Finish
echo ""
echo "==> [6/6] Verifying installation..."
echo "  -> agy-box binary test:"
if "${BIN_INSTALL_DIR}/agy-box" --version >/dev/null 2>&1; then
  echo "     ✓ agy-box: $("${BIN_INSTALL_DIR}/agy-box" --version 2>&1)"
else
  echo "     ! Host agy binary not detected in PATH; agy-box will run entirely inside container"
fi

echo "  -> codex-box binary test:"
if "${BIN_INSTALL_DIR}/codex-box" --version >/dev/null 2>&1; then
  echo "     ✓ codex-box: $("${BIN_INSTALL_DIR}/codex-box" --version 2>&1)"
else
  echo "     ! Host codex binary not detected in PATH; codex-box will run entirely inside container"
fi

echo "  -> claude-box binary test:"
if "${BIN_INSTALL_DIR}/claude-box" --version >/dev/null 2>&1; then
  echo "     ✓ claude-box: $("${BIN_INSTALL_DIR}/claude-box" --version 2>&1)"
else
  echo "     ! Host claude binary not detected in PATH; claude-box will run entirely inside container"
fi

echo ""
echo "========================================================================"
echo "  Installation Complete!"
echo "========================================================================"

if [[ ":$PATH:" != *":${BIN_INSTALL_DIR}:"* ]]; then
  echo ""
  echo "Warning: ${BIN_INSTALL_DIR} is not in your PATH."
  echo "Add the following line to your ~/.zshrc or ~/.bashrc:"
  echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
fi

echo ""
echo "Usage:"
echo "  agy-box                   # Run Antigravity CLI interactively in sandbox"
echo "  agy-box --print 'prompt'  # Run non-interactive query"
echo "  codex-box                 # Run Codex CLI interactively in sandbox"
echo "  codex-box app-server      # Run Codex JSON-RPC app-server (for Orca/IDE integration)"
echo "  claude-box                # Run Claude Code CLI interactively in sandbox"
echo "  claude-box -p 'prompt'    # Run non-interactive Claude query"
echo ""
