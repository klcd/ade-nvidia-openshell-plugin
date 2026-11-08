#!/usr/bin/env bash
set -euo pipefail

AGENT="${1:-claude}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIRST="iso-a-$$"
SECOND="iso-b-$$"
cleanup() {
  openshell sandbox delete "$FIRST" >/dev/null 2>&1 || true
  openshell sandbox delete "$SECOND" >/dev/null 2>&1 || true
}
trap cleanup EXIT

case "$AGENT" in
  claude) IMAGE="openshell-claude:latest"; PROVIDER="claude-code"; POLICY="orca-claude.json" ;;
  antigravity|agy) IMAGE="openshell-antigravity:latest"; PROVIDER="antigravity"; POLICY="orca-antigravity.json" ;;
  codex) IMAGE="openshell-codex:latest"; PROVIDER="codex"; POLICY="orca-codex.json" ;;
  *) echo "Unsupported agent: $AGENT" >&2; exit 64 ;;
esac

for name in "$FIRST" "$SECOND"; do
  openshell sandbox create --name "$name" --from "$IMAGE" \
    --detach --provider "$PROVIDER" --policy "$ROOT/policies/$POLICY" \
    -o json >/dev/null
done

first_id="$(openshell sandbox get "$FIRST" -o json | jq -r '.id')"
second_id="$(openshell sandbox get "$SECOND" -o json | jq -r '.id')"
test -n "$first_id" && test "$first_id" != null
test -n "$second_id" && test "$second_id" != null
test "$first_id" != "$second_id"

for name in "$FIRST" "$SECOND"; do
  echo "$name: $(openshell sandbox exec --name "$name" --no-tty --no-login-shell -- sh -c 'readlink /proc/self/ns/pid; readlink /proc/self/ns/mnt; readlink /proc/self/ns/net')"
done

if openshell sandbox exec --name "$FIRST" --no-tty --no-login-shell -- \
  curl --silent --show-error --fail --max-time 10 https://example.com >/dev/null 2>&1; then
  echo 'Unexpected egress to example.com' >&2
  exit 1
fi

echo "Gateway reported distinct managed sandbox IDs: $first_id and $second_id"
echo 'Unlisted example.com egress was denied.'
