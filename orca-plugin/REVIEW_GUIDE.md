# Orca Maintainer Review & Security Audit Guide

This document is prepared for **Orca catalog maintainers and security auditors** reviewing `local.openshell-bridge` (`ade-nvidia-openshell-plugin/orca-plugin`).

It outlines the trust boundary, execution requirements, subprocess boundaries, and copy-paste verification steps to audit this plugin in under 60 seconds.

---

## 1. Quick Audit Summary

| Attribute | State | Notes |
| :--- | :--- | :--- |
| **Execution Tier** | `trusted-worker` | Required for the `agent.launch.before` hook and local `openshell` CLI queries. |
| **Host Capabilities** | **`"capabilities": []`** | **Zero host capabilities requested** (no `pty`, `worktrees`, `git`, `browser`, `shell`, or `network`). |
| **Outbound Network Calls** | **ZERO (`0`)** | No `fetch()`, `http`, `https`, telemetry, tracking, or remote network calls anywhere in `src/`. |
| **Dynamic Code Execution** | **ZERO (`0`)** | No `eval()`, `new Function()`, or obfuscated/minified code. |
| **Subprocess Execution** | **Strictly bounded** | Only calls the local `openshell` binary via `execFile` with explicit argument arrays (never arbitrary `sh -c`). |
| **Failure Mode** | **Fail-closed (`deny`)** | Hook uses `"onError": "deny"` to prevent unintended unconstrained agent launches if an error occurs. |

---

## 2. 30-Second Verification Commands

You can verify all security guarantees locally using standard tools:

```bash
# 1. Run all unit tests (9 tests, 100% passing)
orca plugin test ./orca-plugin --json

# 2. Verify zero network requests in the plugin source
grep -rn "fetch(" orca-plugin/src/

# 3. Verify zero eval or dynamic code execution
grep -rn "eval(" orca-plugin/src/

# 4. Verify zero requested host capabilities
orca plugin inspect ./orca-plugin --json | grep -A 5 '"capabilities"'

# 5. Verify unminified, clean TypeScript & HTML
find orca-plugin/src -name "*.ts"
```

---

## 3. Why `trusted-worker` is Required

Orca provides two execution profiles for plugins with UI:
- `sandboxed-ui`: Runs in an isolated webview with no access to local files or CLI tools.
- `trusted-worker`: Runs a local Node.js process (`src/worker.ts`) to interact with host tools.

This plugin requires `trusted-worker` for two specific, bounded tasks:
1. **The `agent.launch.before` Hook**: When the user launches an agent in Orca (e.g., `claude`, `codex`, or `antigravity`), Orca calls this hook. If the active worktree has sandboxing enabled, the hook rewrites the launch command to run inside a disposable OpenShell Linux sandbox container (`claude-box`, `codex-box`, `agy-box`). If sandboxing is disabled (`Hostmode`), it allows the launch through untouched.
2. **Local Policy & Sandbox State Queries**: The **OpenShell Policies** sidebar panel queries local YAML/JSON policy files (`~/.agents/`) and reads sandbox status from the local `openshell` CLI (`openshell sandbox list`).

---

## 4. Security Invariants & Threat Model

### Invariant A: Strict Hook Allowlist & Injection Prevention
In [`src/worker.ts`](src/worker.ts):
- **Agent Allowlist**: Only known agents (`claude`, `codex`, `antigravity`, `agy`) are processed. All other agent launches pass through untouched.
- **Executable Validation**: The wrapper executable (`claude-box`, etc.) is verified to exist on disk before any command rewrite is returned.
- **Environment Sanitization**: All `OPENSHELL_BRIDGE_*` variables are explicitly stripped from incoming environment variables (`safeEnv`) to prevent malicious injection or tampering.

### Invariant B: Safe Subprocess Execution
In [`src/sandbox/sandbox-control.ts`](src/sandbox/sandbox-control.ts) and [`src/policy/l7-mutator.ts`](src/policy/l7-mutator.ts):
- Every subprocess execution uses `execFile` or `execFileSync` passing a `string[]` argument vector.
- No untrusted input is interpolated into shell command strings.
- Only the `openshell` binary is invoked (resolving from safe path directories).

### Invariant C: Local File System Boundaries
In [`src/parsers/`](src/parsers/) and [`src/state/`](src/state/):
- The worker only reads policy definitions from the user's explicit policy directory (`~/.agents/` or `~/.config/orca-openshell/`).
- It never touches SSH keys, system root files, or credentials outside OpenShell configuration files.

---

## 5. Reviewer Contact
If you have any questions during review, please contact:
- **Repository Maintainer**: [@klcd](https://github.com/klcd)
- **Repository**: [https://github.com/klcd/ade-nvidia-openshell-plugin](https://github.com/klcd/ade-nvidia-openshell-plugin)
