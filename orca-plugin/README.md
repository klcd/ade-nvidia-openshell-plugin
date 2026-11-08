# Orca OpenShell launch hook

This Orca 1.4.248+ trusted worker plugin rewrites terminal launches of Claude Code,
Google Antigravity, and OpenAI Codex to the `claude-box`, `agy-box`, and
`codex-box` executables. It applies to `agent launch` and terminal
`orchestration worker-start` launches. It denies these launches when the wrapper
is missing or Orca's command cannot be safely rewritten. Plugin hook errors also
deny the launch.

The plugin sets `OPENSHELL_BRIDGE_REQUIRED=1`, selects the corresponding policy
from `~/.agents/orca-openshell-policies`, and forwards `OPENSHELL_BRIDGE_TERMINAL_ID`
and `OPENSHELL_BRIDGE_WORKSPACE_ID` when present so the bridge can bind a
host-side FIFO delegation broker for in-sandbox orchestration. The bridge refuses
standalone fast paths and requires a filesystem policy with hard Landlock
compatibility (merging any project-level `<project>/.agents/policies/` on top).
The wrapper location defaults to `~/.local/bin` and can be set with
`ORCA_OPENSHELL_BRIDGE_BIN_DIR` in the Orca runtime environment. Set
`ORCA_OPENSHELL_POLICY_DIR` to use another policy directory.

Orca does not invoke this hook for structured chats or restored sessions. See
[`../docs/ORCA_INTEGRATION.md`](../docs/ORCA_INTEGRATION.md) for full details.

```sh
orca plugin validate orca-plugin --json
orca plugin test orca-plugin --json
orca plugin install "$(pwd)/orca-plugin" --json
```

The install command returns an Orca approval fingerprint for this trusted code.
Review the grant and rerun with its exact `--approve` argument if prompted.
