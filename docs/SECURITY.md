# ADE NVIDIA OpenShell Plugin — Security Notes

Each run creates a disposable Linux sandbox through OpenShell. The policy applies filesystem restrictions through Landlock and network restrictions through OpenShell's supervisor. Review the actual policy and provider profile in `policies/` and `profiles/` before use.

## Workspace access

The bridge uploads the project workspace when it creates a sandbox, including files ignored by Git. A normal standalone session can read and write the workspace. A Paseo delegated session can read it, but writes are restricted to paths listed in `ORCA_SANDBOX_WRITE_PATHS`; without that variable, no project paths are writable. Treat uploaded files as visible to the agent, and do not keep secrets in the workspace unless the configured policy and agent access are appropriate.

At shutdown, the bridge downloads permitted workspace changes and deletes the sandbox. A forced host shutdown can interrupt cleanup and synchronization.

## Credentials

The bridge discovers supported credentials from host environment variables or agent configuration, registers them with the matching OpenShell provider, and replaces recognized values in staged text files with OpenShell placeholders. It checks staged files and workspace contents for exact occurrences of discovered credentials before upload.

These measures have limits: the scan covers only credentials the bridge discovered, and the supervisor's regex redaction recognizes only its built-in token patterns. Neither mechanism is a general secret scanner. Review files before running agents, especially when the workspace contains `.env`, local config, or ignored files.

## Policy checks

`ORCA_SANDBOX_BOUNDARY_POLICY` enables an `openshell-prover` comparison before sandbox creation. The bridge stops if the checker is unavailable or does not confirm filesystem containment. Keep the boundary policy under trusted administrative control.
