#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="${ORCA_OPENSHELL_BRIDGE_BIN_DIR:-$HOME/.local/bin}"
POLICY_DIR="${ORCA_OPENSHELL_POLICY_DIR:-$HOME/.agents/orca-openshell-policies}"

(cd "$ROOT/ts" && bun build src/cli.ts --outfile=dist/agent-box.bundle.js --target=node)
(cd "$ROOT/ts" && bun build src/delegation-admin.ts --outfile=dist/orca-delegation.bundle.js --target=node)
(cd "$ROOT/ts" && bun build src/setup-codex-provider.ts --outfile=dist/orca-codex-provider-setup.bundle.js --target=node)
openshell provider profile lint --file "$ROOT/profiles/codex-orca.profile.yaml" >/dev/null
PROFILE_TMP_DIR="$(mktemp -d)"
PROFILE_EXPORT="$PROFILE_TMP_DIR/current.json"
PROFILE_UPDATE="$PROFILE_TMP_DIR/codex-orca.yaml"
trap 'rm -rf "$PROFILE_TMP_DIR"' EXIT
if openshell provider profile export --global --output json codex-orca >"$PROFILE_EXPORT" 2>/dev/null; then
  python3 - "$ROOT/profiles/codex-orca.profile.yaml" "$PROFILE_UPDATE" "$PROFILE_EXPORT" <<'PY'
import json,re,sys
source, destination, current = sys.argv[1:]
version = json.load(open(current))['resource_version']
content = open(source).read()
content, count = re.subn(r'^resource_version: \d+$', f'resource_version: {version}', content, count=1, flags=re.M)
if count != 1: raise SystemExit('Profile resource_version missing')
open(destination, 'w').write(content)
PY
  openshell provider profile update --global --file "$PROFILE_UPDATE" codex-orca >/dev/null
else
  openshell provider profile import --global --file "$ROOT/profiles/codex-orca.profile.yaml" >/dev/null
fi
mkdir -p "$BIN_DIR" "$POLICY_DIR"
install -m 755 "$ROOT/ts/dist/agent-box.bundle.js" "$BIN_DIR/agent-box"
install -m 755 "$ROOT/ts/src/delegation-shim.js" "$BIN_DIR/orca-delegation-shim.js"
install -m 755 "$ROOT/ts/dist/orca-delegation.bundle.js" "$BIN_DIR/orca-delegation"
install -m 755 "$ROOT/ts/dist/orca-codex-provider-setup.bundle.js" "$BIN_DIR/orca-codex-provider-setup"
ln -sfn "$BIN_DIR/agent-box" "$BIN_DIR/codex-box"
ln -sfn "$BIN_DIR/agent-box" "$BIN_DIR/claude-box"
ln -sfn "$BIN_DIR/agent-box" "$BIN_DIR/agy-box"
install -m 644 "$ROOT/policies/orca-codex.json" "$POLICY_DIR/codex.json"
install -m 644 "$ROOT/policies/orca-claude.json" "$POLICY_DIR/claude.json"
install -m 644 "$ROOT/policies/orca-antigravity.json" "$POLICY_DIR/antigravity.json"
install -m 644 "$ROOT/policies/orca-antigravity.json" "$POLICY_DIR/agy.json"
orca plugin validate "$ROOT/orca-plugin" --json
if [[ -x "/Applications/Orca.app/Contents/MacOS/Orca" && -f "/Applications/Orca.app/Contents/Resources/app.asar.unpacked/out/cli/runtime-client.js" ]]; then
  ELECTRON_RUN_AS_NODE=1 /Applications/Orca.app/Contents/MacOS/Orca -e '
const { RuntimeClient } = require("/Applications/Orca.app/Contents/Resources/app.asar.unpacked/out/cli/runtime-client.js");
const binDir = process.argv[1];
(async () => {
  const client = new RuntimeClient();
  for (const [agent, bin] of [["claude", "claude-box"], ["codex", "codex-box"], ["antigravity", "agy-box"]]) {
    await client.call("settings.mutateAgentLaunch", { type: "command", agent, value: `${binDir}/${bin}` });
  }
})().catch(() => {});
' "$BIN_DIR" || true
fi
echo "Bridge and Orca policies installed. Review and run:"
echo "  orca plugin install '$ROOT/orca-plugin' --json"
