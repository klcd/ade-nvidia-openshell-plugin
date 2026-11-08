# Orca OpenShell Bridge & Policy Inspector Plugin (`local.openshell-bridge`)

This Orca 1.4.248+ trusted worker plugin (`v0.3.0`) provides:

1. **Automatic OpenShell Launch Hook (`agent.launch.before`)**:
   Rewrites terminal launches of Claude Code, Google Antigravity, and OpenAI Codex to the `claude-box`, `agy-box`, and `codex-box` executables (`agent launch` and terminal `orchestration worker-start`). Denies launches when the wrapper is missing or Orca's command cannot be safely rewritten.
2. **OpenShell Policies & CLI Compatibility Panel (`OpenShell Policies`)**:
   A rich right-sidebar panel (`panel/index.html`) and status bar item (`OpenShell: Enforced`) that inspect and couple all active security policies to their compatible CLI commands:
   - **Interactive CLI Command Evaluator**: Test any command (e.g., `git status`, `orca orchestration worker-start --spec "run tests" --agent claude`, `git push --force`) against `DENY > ASK > ALLOW` permission rules, the OpenShell FIFO delegation shim, Landlock filesystem boundaries, and network egress rules.
   - **CLI Commands Tab**: Lists all canonical `.agents/permissions/*.yml` rules (`allow` / `ask` / `deny`) coupled directly to their compatible CLI syntax (`git status [args...]`, `docker ps [args...]`, `kubectl get [args...]`, etc.), base binary, scope (`global` vs `workspace`), and native config sync state (`.claude/settings.json`, `.codex/rules/default.rules`, `.gemini/settings.json`).
   - **Agent Sandboxes & Egress Tab**: Shows `claude-box`, `codex-box`, and `agy-box` launch commands (`orca agent launch --agent ... --surface chat|terminal`), Landlock read-write/read-only filesystem mounts, and allowed HTTPS egress endpoints coupled to compatible CLI tools (`curl`, `npm`, `gh`, etc.).
   - **Orchestration CLI Tab**: Displays `.agents/delegation.json` policy, active host delegation grants, allowed `orca orchestration` subcommands inside sandboxes, and blocked flags.
3. **Command Palette Action (`openshell.inspectPolicies`)**:
   Run **OpenShell: Inspect Allowed Policies & CLI Commands** from the command palette (or click the `OpenShell` status bar item) to inspect a summary of allowed CLI commands and policies.

The plugin sets `OPENSHELL_BRIDGE_REQUIRED=1`, selects the corresponding policy from `~/.agents/orca-openshell-policies`, and forwards `OPENSHELL_BRIDGE_TERMINAL_ID` and `OPENSHELL_BRIDGE_WORKSPACE_ID` when present so the bridge can bind a host-side FIFO delegation broker for in-sandbox orchestration. The bridge refuses standalone fast paths and requires a filesystem policy with hard Landlock compatibility (merging any project-level `<project>/.agents/policies/` on top). The wrapper location defaults to `~/.local/bin` and can be set with `ORCA_OPENSHELL_BRIDGE_BIN_DIR` in the Orca runtime environment. Set `ORCA_OPENSHELL_POLICY_DIR` to use another policy directory.

For Chat Mode (`surface: "chat"`), `./scripts/install-orca-host.sh` configures Orca's `agentCmdOverrides` to route structured sessions through `claude-box` and `codex-box` over full-duplex OpenShell SSH streaming. See [`../docs/ORCA_INTEGRATION.md`](../docs/ORCA_INTEGRATION.md) for full details.

```sh
orca plugin check orca-plugin --json
orca plugin test orca-plugin --json
orca plugin install "$(pwd)/orca-plugin" --json
orca plugin open local.openshell-bridge --panel policies --json
```

The install command returns an Orca approval fingerprint for this trusted code. Review the grant and rerun with its exact `--approve` argument if prompted.
