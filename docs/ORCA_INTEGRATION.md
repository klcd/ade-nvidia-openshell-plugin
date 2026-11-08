# Orca orchestration through OpenShell

Verified with Orca 1.4.253 and OpenShell 0.1.2 on 2026-11-08. This tree copies
the existing sibling `orca-openshell-bridge` checkout and extends that bridge;
the original checkout was not replaced.

## Runtime boundary

Orca's installed `agent.launch.before` hook rewrites terminal Codex, Claude, and
Antigravity launches to the `codex-box`, `claude-box`, and `agy-box` wrappers.
Each wrapper creates a new named OpenShell sandbox, uploads the workspace,
streams the agent terminal, merges nonconflicting edits back, and deletes the
sandbox on exit. Orca still owns Runs, Tasks, Dispatches, mail, and completion
records.

```
Orca runtime -> launch hook -> existing bridge -> OpenShell mTLS gateway
      ^                                      |
      | fixed Orca CLI calls                 | one sandbox per agent
host-side delegation broker <- FIFO over OpenShell exec <- sandboxed orca shim
```

The host broker receives the terminal and workspace IDs from Orca's hook. Its
private grant file names the allowed agents, exact workspace, maximum total
worker launch attempts, and maximum nesting depth. It accepts only a bounded
subset of `worker-start`, `worker-show`, `worker-read`, `check`, `reply`, and
`send`; it supplies `--from` and workspace itself. It rejects remote placement,
caller identity overrides, unknown agent types, and unsupported CLI verbs. The
sandbox receives no Orca runtime token, socket, OpenShell gateway credential, or
host Docker socket. The FIFO uses OpenShell's exec channel and needs no network
egress.

For `worker-start`, the broker uses `orca agent launch --surface terminal`,
checks the new terminal's bridge marker and distinct Ready sandbox ID in the
OpenShell gateway, waits for `tui-idle`, and then calls
`orca orchestration worker-start --terminal`. This forces the terminal launch
hook even if the user's default is Orca Chat. The worker receives its own grant
at one deeper nesting level so it can send `worker_done`. `--max-depth 1` denies
worker-created grandchildren. If `worker-start` fails after the terminal was
pre-created, the broker automatically revokes the grant, releases any partial
dispatch, and closes the pre-created worker terminal.

For Claude Code, `ClaudeAdapter` discovers hash-suffixed macOS Keychain items
(`Claude Code-credentials-*`), provisions only the profile-accepted
`CLAUDE_CODE_OAUTH_TOKEN` credential into the OpenShell gateway, and strips
legacy `:*|` permission rules from staged `/sandbox/.claude/settings.json` so
Claude Code v2.1 reaches the idle prompt without blocking on an interactive
settings warning.

Orca Codex launches use a separate `codex-orca` provider profile. Only access
token and account ID are injectable. The host setup command stores OAuth
refresh material in the gateway and rotates the access token. The staged
`auth.json` has placeholders and a synthetic, non-secret ID token because
Codex parses that field locally. Orca Codex launch fails closed until this
provider has refresh configuration. The standalone Codex bridge keeps its
existing provider path. This follows NVIDIA's
[Codex OpenShell example](https://github.com/NVIDIA/OpenShell/blob/main/examples/codex-app-server/README.md)
and [OAuth placeholder finding](https://github.com/NVIDIA/OpenShell/issues/988).

For Orca launches, workspace sync captures a launch-time file snapshot and
downloads the sandbox result to a temporary directory. It applies a sandbox
edit only when the host file still matches that snapshot. Simultaneous edits
stay on the host; sandbox versions go to
`~/.orca/openshell-conflicts/<sandbox-name>/`. `.git` metadata and sandbox
symlinks are never copied back. This prevents a closing agent from overwriting
host changes made while it ran.

## Install and activate

Run on the Orca/OpenShell host from this repository:

```sh
./install.sh
scripts/install-orca-host.sh
orca plugin install "$(pwd)/orca-plugin" --json
```

Orca retains the approval for an update with the same access. If it requests
new approval, review the exact fingerprint before installing. The host script
installs the bridge, restricted shim, grant command, Orca policies, and the
`codex-orca` profile. It does not read or upload host OAuth tokens.

Launch a coordinator in an exact Orca workspace and grant that terminal:

```sh
orca worktree current --json
orca agent launch --agent claude --surface terminal --worktree 'id:<workspace-id>' --json
~/.local/bin/orca-delegation grant \
  --terminal '<handle-from-launch>' --workspace 'id:<workspace-id>' \
  --agents claude,antigravity,codex --max-workers 2 --max-depth 1
```

Alternatively, enable automatic depth-0 coordinator grants by setting
`ORCA_AUTO_GRANT_DELEGATION=1` on the host or creating `<project>/.agents/delegation.json`:

```json
{
  "autoGrant": true,
  "agents": ["claude", "antigravity", "codex"],
  "maxWorkers": 2,
  "maxDepth": 1
}
```

The grant command verifies that the terminal is a supported Orca agent in the
named workspace. Revoke with `~/.local/bin/orca-delegation revoke --terminal
'<handle>'`. The bridge also removes its grant when the terminal exits.
Inside the coordinator, use ordinary Orca orchestration commands:

```sh
orca orchestration worker-start --spec 'Task description' --agent claude --worktree current --json
orca orchestration worker-show --dispatch '<dispatch-id>' --json
orca orchestration worker-read --dispatch '<dispatch-id>' --json
orca orchestration check --peek --json
```

The shim also translates `--spec-file <path|->` by reading the file or stdin
inside the sandbox. It never asks the host to read a sandbox-supplied path.

## Policies and support

`policies/orca-codex.json`, `policies/orca-claude.json`, and
`policies/orca-antigravity.json` require hard Landlock and have no explicit
network destinations. Any repository-specific policies in `<project>/.agents/policies/`
are merged on top of the base Orca policy while preserving the hard Landlock
requirement. Attached provider profiles allow only their listed model API hosts
on port 443. There is no Orca runtime network rule; the coordinator talks to its
broker through local FIFOs and OpenShell exec. Coordinator and worker egress
policies are currently the same because the Orca launch hook does not identify
worker role. Per-workspace write scopes can be configured with
`ORCA_SANDBOX_WRITE_PATHS` on the host.

OpenCode remains unsupported because this bridge has no OpenCode runner or
image. Structured Chat agents and saved-session restores do not pass through
Orca's terminal launch hook and are outside this integration.

## Verification

```sh
node ts/node_modules/typescript/bin/tsc --noEmit -p ts/tsconfig.json
node ts/node_modules/typescript/bin/tsc --noEmit -p orca-plugin/tsconfig.json
bun test ts/src/*.test.ts
orca plugin validate orca-plugin --json
orca plugin test orca-plugin --json
scripts/smoke-bridge.sh claude
scripts/smoke-isolation.sh claude
scripts/smoke-delegation-transport.sh claude
scripts/smoke-orca-worker.sh '<coordinator-handle>' '<workspace-id>' '<coordinator-sandbox-name>' claude
```

All unit tests, plugin validation/tests, profile lint, standalone launches
(`claude-box` and `agy-box`), isolation smoke tests, delegation transport smoke
tests, and the full end-to-end in-sandbox worker delegation test
(`scripts/smoke-orca-worker.sh`) have been verified live:

- Coordinator sandbox `cc-safe-o-i5189a75` (`0ce2e5c7-0aa7-40be-8cf1-b395005c2077`)
  delegated `worker-start` over the FIFO bridge.
- Host broker launched worker sandbox `cc-safe-o-3w7f97c1`
  (`8d996f7d-9181-4104-8e6d-e3ad2ef8f2a3`) with verified distinct `pid`, `mnt`,
  and `net` namespaces.
- Orca dispatch `ctx_e1ed4c1cc57a` executed the task inside the worker sandbox
  and completed with `state: succeeded`.
