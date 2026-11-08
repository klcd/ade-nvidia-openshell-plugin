#!/usr/bin/env bash
set -euo pipefail

AGENT="${1:-claude}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/orca-bridge-smoke.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

case "$AGENT" in
  claude) IMAGE="openshell-claude:latest"; WRAPPER="claude-box"; POLICY="orca-claude.json" ;;
  antigravity|agy) IMAGE="openshell-antigravity:latest"; WRAPPER="agy-box"; POLICY="orca-antigravity.json" ;;
  codex) IMAGE="openshell-codex:latest"; WRAPPER="codex-box"; POLICY="orca-codex.json" ;;
  *) echo "Unsupported agent: $AGENT" >&2; exit 64 ;;
esac

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "Missing $IMAGE; run ./install.sh first" >&2
  exit 1
fi

(cd "$ROOT/ts" && bun build src/cli.ts --outfile=dist/agent-box.bundle.js --target=node)
ln -s "$ROOT/ts/dist/agent-box.bundle.js" "$WORK/$WRAPPER"
mkdir "$WORK/project"
(
  cd "$WORK/project"
  ORCA_OPENSHELL_REQUIRED=1 \
    ORCA_OPENSHELL_POLICY_FILE="$ROOT/policies/$POLICY" \
    "$WORK/$WRAPPER" --version
)

echo "Bridge returned successfully after a real OpenShell sandbox launch ($AGENT)."
echo "Inspect ~/.orca/openshell-bridge.log for the sandbox name and cleanup."
