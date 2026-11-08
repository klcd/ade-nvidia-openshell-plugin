---
name: openshell-egress-popup
description: Prompt the user with an interactive in-chat popup whenever OpenShell blocks a network egress request (e.g. curl/fetch/gh/npm connection refused or 403) and dynamically apply the approved L7 HTTP policy rule.
---

# OpenShell Dynamic L7 Egress Popup Skill

Whenever a shell command inside the OpenShell sandbox fails due to network egress blocking (for example `curl: (7) Failed to connect`, `403 Forbidden` from the OpenShell supervisor proxy, or `[OpenShell Egress Blocked]` in stderr):

1. **Prompt via In-Chat Popup**:
   Immediately call the interactive question tool (`ask_question` in Antigravity, `AskUserQuestion` in Claude Code, or `request_user_input` in Codex) to show a clean popup modal in the chat with these choices:
   - `(Recommended) Allow for this session only (live hot-reload via openshell policy update)`
   - `Allow and save for this project (.agents/policies/l7-custom.json + live hot-reload)`
   - `Allow in general for all projects (~/.agents/orca-openshell-policies + live hot-reload)`
   - `Keep blocked`

2. **Apply the Rule Dynamically**:
   Based on the user's popup selection (`session`, `workspace`, or `global`), run:
   ```bash
   openshell-l7-allow --scope <session|workspace|global> --host <domain> --port <port> --method <GET|POST|...> --path "<path-or-/**>"
   ```
   and then re-run the blocked command to verify it succeeds.
