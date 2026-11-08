---
name: openshell-egress-popup
description: Handle OpenShell L7 network egress blocks in 2 LLM turns by letting agent-box intercept the blocked request, display the approval popup, hot-reload the sandbox policy, and retry inside the same run_command call.
---

# OpenShell Dynamic L7 Egress Popup Skill (2-LLM-Request Flow)

When running network commands (`curl`, `wget`, `gh`, `npm`, `bun`, etc.) inside the OpenShell sandbox:

1. **Single-Turn Interception & Retry (2 LLM Requests Total)**:
   - Always set `WaitMsBeforeAsync: 10000` on `run_command` when executing network requests.
   - If OpenShell blocks the outbound request (DNS/TCP refusal or L7 HTTP `403 Forbidden`), `agent-box` (`runAgyChatExec`) **automatically intercepts the block before returning to the LLM**, displays an interactive popup modal (`Session only`, `Project`, `Global`, or `Keep Blocked`), hot-reloads the OpenShell sandbox policy via `openshell policy update`, and **automatically retries the command inside the exact same `run_command` invocation**.
   - As a result, the entire flow uses **only 2 LLM requests**:
     1. **Request 1**: LLM invokes `run_command("curl ...")` (user approves in popup $\rightarrow$ policy reloads $\rightarrow$ command retries and returns `200 OK`).
     2. **Request 2**: LLM receives the `200 OK` output and summarizes the result for the user.
2. **If the User Clicks "Keep Blocked"**:
   - `run_command` will output `[OpenShell Egress Denied by User]`. Do **not** prompt again or call `openshell-l7-allow`; simply report to the user that the request remained blocked as chosen.
