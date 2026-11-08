#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 3 ]]; then
  echo "Usage: $0 <coordinator-terminal-handle> <orca-workspace-id> <coordinator-sandbox-name> [agent]" >&2
  exit 64
fi
COORDINATOR="$1"
WORKSPACE="$2"
COORDINATOR_SANDBOX="$3"
AGENT="${4:-claude}"
SPEC='OpenShell orchestration smoke test: reply with READY, then send worker_done with outcome succeeded. Do not modify files.'
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

~/.local/bin/orca-delegation grant --terminal "$COORDINATOR" --workspace "id:$WORKSPACE" \
  --agents "$AGENT" --max-workers 1 --max-depth 1
DIR="$(openshell sandbox exec --name "$COORDINATOR_SANDBOX" --no-tty --no-login-shell -- sh -c 'ls -d /tmp/orca-delegate-*' | head -1)"
if [[ ! "$DIR" =~ ^/tmp/orca-delegate-[a-f0-9-]+$ ]]; then
  echo "No delegation FIFO in coordinator sandbox" >&2
  exit 1
fi

set +e
openshell sandbox exec --name "$COORDINATOR_SANDBOX" --no-tty --no-login-shell \
  --env "ORCA_DELEGATION_DIR=$DIR" \
  --env PATH=/sandbox/.orca-delegate/bin:/usr/local/bin:/usr/bin:/bin \
  -- orca orchestration worker-start --spec "$SPEC" --agent "$AGENT" --json >"$TMP/start.json"
START_CODE=$?
set -e
if [[ "$START_CODE" -ne 0 ]]; then
  cat "$TMP/start.json"
  echo "Worker start failed. Inspect the dispatch and use Orca worker-release; a pre-created terminal may require operator cleanup." >&2
  exit "$START_CODE"
fi

python3 - "$TMP/start.json" "$TMP/receipt" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))['result']
for key in ('dispatchId','taskId','terminal'):
    if not d.get(key): raise SystemExit(f'No {key} in Orca worker receipt')
open(sys.argv[2],'w').write('\n'.join(d[k] for k in ('dispatchId','taskId','terminal')))
PY
DISPATCH="$(sed -n '1p' "$TMP/receipt")"
WORKER_TERMINAL="$(sed -n '3p' "$TMP/receipt")"
WORKER_SANDBOX="$(python3 - "$WORKER_TERMINAL" <<'PY'
import hashlib,json,os,sys
key=hashlib.sha256(sys.argv[1].encode()).hexdigest()
path=os.path.expanduser(f'~/.agents/orca-openshell-delegation/launches/{key}.json')
print(json.load(open(path))['sandbox'])
PY
)"

openshell sandbox list -o json >"$TMP/sandboxes.json"
python3 - "$TMP/sandboxes.json" "$COORDINATOR_SANDBOX" "$WORKER_SANDBOX" <<'PY'
import json,sys
rows={row['name']:row for row in json.load(open(sys.argv[1]))['sandboxes']}
a,b=rows.get(sys.argv[2]),rows.get(sys.argv[3])
if not a or not b or a['id']==b['id'] or a['phase']!='Ready' or b['phase']!='Ready':
    raise SystemExit('Gateway did not verify distinct ready coordinator and worker sandboxes')
print(f"Gateway isolation: coordinator={a['id']} worker={b['id']}")
PY
for kind in pid mnt net; do
  A="$(openshell sandbox exec --name "$COORDINATOR_SANDBOX" --no-tty --no-login-shell -- readlink "/proc/self/ns/$kind")"
  B="$(openshell sandbox exec --name "$WORKER_SANDBOX" --no-tty --no-login-shell -- readlink "/proc/self/ns/$kind")"
  if [[ "$A" == "$B" ]]; then echo "Shared $kind namespace" >&2; exit 1; fi
  echo "$kind namespaces differ: $A / $B"
done

for ((i=0; i<24; i++)); do
  orca orchestration worker-show --dispatch "$DISPATCH" --json >"$TMP/show.json"
  STATE="$(python3 - "$TMP/show.json" <<'PY'
import json,sys
print(json.load(open(sys.argv[1]))['result'].get('state','unknown'))
PY
)"
  if [[ "$STATE" == succeeded ]]; then
    echo "PASS: Orca dispatch $DISPATCH completed in sandbox $WORKER_SANDBOX"
    exit 0
  fi
  if [[ "$STATE" == failed || "$STATE" == canceled ]]; then
    cat "$TMP/show.json"
    exit 1
  fi
  sleep 5
done
echo "Dispatch $DISPATCH did not complete within 120 seconds; inspect it before cleanup" >&2
exit 1
