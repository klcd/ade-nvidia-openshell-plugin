#!/usr/bin/env bash
set -euo pipefail

AGENT="${1:-claude}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAME="dl-$RANDOM-$RANDOM"
cleanup() { openshell sandbox delete "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

case "$AGENT" in
  claude) IMAGE="openshell-claude:latest"; PROVIDER="claude-code"; POLICY="orca-claude.json" ;;
  antigravity|agy) IMAGE="openshell-antigravity:latest"; PROVIDER="antigravity"; POLICY="orca-antigravity.json" ;;
  codex) IMAGE="openshell-codex:latest"; PROVIDER="codex"; POLICY="orca-codex.json" ;;
  *) echo "Unsupported agent: $AGENT" >&2; exit 64 ;;
esac

openshell sandbox create --name "$NAME" --from "$IMAGE" --detach \
  --provider "$PROVIDER" --policy "$ROOT/policies/$POLICY" -o json >/dev/null
openshell sandbox exec --name "$NAME" --no-tty --no-login-shell -- mkdir -p /sandbox/.orca-delegate/bin
openshell sandbox upload "$NAME" "$ROOT/ts/src/delegation-shim.js" /sandbox/.orca-delegate/bin/orca >/dev/null
openshell sandbox exec --name "$NAME" --no-tty --no-login-shell -- sh -c \
  'printf "%s\n" "{\"type\":\"module\"}" > /sandbox/.orca-delegate/package.json && chmod 755 /sandbox/.orca-delegate/bin/orca'

cd "$ROOT"
TEST_SANDBOX_NAME="$NAME" bun -e '
  import { DelegationBroker } from "./ts/src/delegation.ts";
  import { spawn } from "node:child_process";
  const broker = new DelegationBroker(process.env.TEST_SANDBOX_NAME, "ungranted-test-terminal", "ungranted-test-workspace", process.cwd());
  broker.start();
  try {
    const child = spawn("openshell", ["sandbox", "exec", "--name", process.env.TEST_SANDBOX_NAME,
      "--no-tty", "--no-login-shell", "--env", `ORCA_DELEGATION_DIR=${broker.sandboxDir}`,
      "--", "node", "/sandbox/.orca-delegate/bin/orca", "orchestration", "check", "--peek", "--json"],
      { stdio: ["ignore", "pipe", "pipe"] });
    const chunks = [];
    child.stderr.on("data", chunk => chunks.push(String(chunk)));
    const code = await new Promise(resolve => child.on("close", resolve));
    if (code !== 77 || !chunks.join("").includes("not granted")) throw new Error(`Expected scoped denial, got ${code}: ${chunks.join("")}`);
    console.log("PASS: sandbox request reached host broker; ungranted identity was denied");
  } finally { broker.stop(); }
'
