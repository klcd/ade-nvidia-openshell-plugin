import { panelState } from '../state.ts'
import { escapeHtml } from '../utils.ts'

function isSectionOpen(sectionId: string, defaultOpen = true): boolean {
  if (defaultOpen) {
    return !panelState.closedSections.has(sectionId)
  }
  return panelState.openSections.has(sectionId)
}

export function renderSettingsTab(): string {
  const report = panelState.currentReport
  if (!report) return ''

  const defaultEnabled = report.defaultSandboxEnabled === true
  const ws = report.selectedWorkspace
  const inheritedFrom = report.sandboxInheritedFrom || null
  const worktreeStateLabel = report.sandboxEnabled
    ? 'Sandbox (Enforced)'
    : inheritedFrom
      ? `Host Mode (Inherited from ${inheritedFrom.split('/').filter(Boolean).pop() || inheritedFrom})`
      : 'Host Mode (Off)'

  const defaultModeControlHtml = `
    <div class="cmd-row" style="justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap;">
      <div style="display:flex;flex-direction:column;gap:2px;min-width:0;flex:1;">
        <span style="font-size:11px;font-weight:600;color:var(--fg);">Default Sandbox State</span>
        <span class="sub">Global default for new or unconfigured worktrees (override per worktree using the top <code class="mono">Sandbox</code> toggle).</span>
      </div>
      <select id="defaultSandboxModeSelect" style="max-width:150px;flex-shrink:0;" title="Default OpenShell sandbox state for unconfigured worktrees">
        <option value="off" ${!defaultEnabled ? 'selected' : ''}>Off (Host Mode)</option>
        <option value="on" ${defaultEnabled ? 'selected' : ''}>On (Enforced)</option>
      </select>
    </div>
  `

  const idleSec =
    typeof report.sandboxIdleTimeoutSeconds === 'number' ? report.sandboxIdleTimeoutSeconds : 300
  const presetIdleValues = [0, 60, 180, 300, 600, 900]
  const customIdleOption = !presetIdleValues.includes(idleSec)
    ? `<option value="${idleSec}" selected>${idleSec}s (Custom)</option>`
    : ''
  const idleControlHtml = `
    <div class="cmd-row" style="justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap;">
      <div style="display:flex;flex-direction:column;gap:2px;min-width:0;flex:1;">
        <span style="font-size:11px;font-weight:600;color:var(--fg);">Auto-Pause When Idle</span>
        <span class="sub">Per-tab setting: stops this tab's idle container while preserving <code class="mono">/sandbox</code> &amp; L7 policies; restarts automatically on next turn or command.</span>
      </div>
      <select id="idleTimeoutSelect" style="max-width:150px;flex-shrink:0;" title="Idle duration before this tab's sandbox container automatically pauses">
        <option value="0" ${idleSec === 0 ? 'selected' : ''}>Off (Always On)</option>
        <option value="60" ${idleSec === 60 ? 'selected' : ''}>1 minute</option>
        <option value="180" ${idleSec === 180 ? 'selected' : ''}>3 minutes</option>
        <option value="300" ${idleSec === 300 ? 'selected' : ''}>5 minutes</option>
        <option value="600" ${idleSec === 600 ? 'selected' : ''}>10 minutes</option>
        <option value="900" ${idleSec === 900 ? 'selected' : ''}>15 minutes</option>
        ${customIdleOption}
      </select>
    </div>
  `

  const worktreeModeRowHtml = `
    <div class="cmd-row" data-tooltip="Worktree: ${escapeHtml(ws.path)}">
      <div style="display:flex;flex-direction:column;gap:2px;min-width:0;flex:1;">
        <span style="font-size:11px;font-weight:600;color:var(--fg);">Current Worktree Mode</span>
        <span class="sub" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escapeHtml(ws.name)} &mdash; ${escapeHtml(worktreeStateLabel)}</span>
      </div>
      <span class="badge ${report.sandboxEnabled ? 'allow' : 'warn'}">${report.sandboxEnabled ? 'SANDBOX' : 'HOST'}</span>
    </div>
  `

  const del = report.delegation
  const delegationRowsHtml = `
    <div class="cmd-row">
      <div style="display:flex;flex-direction:column;gap:2px;min-width:0;flex:1;">
        <span style="font-size:11px;font-weight:600;color:var(--fg);">Auto-Grant Coordinator Delegation</span>
        <span class="sub">${del?.configPath ? `Configured via <code class="mono">${escapeHtml(del.configPath)}</code>` : 'Set <code class="mono">ORCA_AUTO_GRANT_DELEGATION=1</code> or create <code class="mono">.agents/delegation.json</code>.'}</span>
      </div>
      <span class="badge ${del?.autoGrantEnabled ? 'allow' : 'neutral'}">${del?.autoGrantEnabled ? 'ON' : 'MANUAL'}</span>
    </div>
    <div class="cmd-row">
      <div style="display:flex;flex-direction:column;gap:2px;min-width:0;flex:1;">
        <span style="font-size:11px;font-weight:600;color:var(--fg);">Worker Limits &amp; Active Grants</span>
        <span class="sub">Agents: ${escapeHtml((del?.allowedAgents || []).join(', '))} &bull; Max workers: ${escapeHtml(String(del?.maxWorkers ?? 2))} &bull; Max depth: ${escapeHtml(String(del?.maxDepth ?? 1))}</span>
      </div>
      <span class="source-pill">${escapeHtml(String(del?.activeGrants?.length || 0))} active</span>
    </div>
  `

  const setup = report.setup
  const pathsHtml = `
    <div class="cmd-row" data-tooltip="Per-worktree Sandbox/Host state and Auto-Pause idle timers">
      <div style="display:flex;flex-direction:column;gap:1px;min-width:0;flex:1;">
        <span style="font-size:11px;font-weight:600;color:var(--fg);">Sandbox Mode State File</span>
        <span class="cmd-code sub">~/.config/orca-openshell/sandbox-mode.json</span>
      </div>
      <span class="source-pill">&#8984; state</span>
    </div>
    <div class="cmd-row" data-tooltip="Project-level and temporary subagent OpenShell L7 policies">
      <div style="display:flex;flex-direction:column;gap:1px;min-width:0;flex:1;">
        <span style="font-size:11px;font-weight:600;color:var(--fg);">Project Policy Directory</span>
        <span class="cmd-code sub" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escapeHtml(ws.path)}/.agents/policies</span>
      </div>
      <span class="source-pill">&#8984; project</span>
    </div>
    <div class="cmd-row" data-tooltip="Global Orca OpenShell agent L7 policies">
      <div style="display:flex;flex-direction:column;gap:1px;min-width:0;flex:1;">
        <span style="font-size:11px;font-weight:600;color:var(--fg);">Global L7 Policy Directory</span>
        <span class="cmd-code sub" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escapeHtml(setup?.policyDir || '~/.agents/orca-openshell-policies')}</span>
      </div>
      <span class="source-pill">&#8984; global</span>
    </div>
  `

  return `
    <details class="app-fold" data-section="settings-sandbox" ${isSectionOpen('settings-sandbox', true) ? 'open' : ''}>
      <summary>
        <div style="display:flex;align-items:center;gap:8px;">
          <span class="fold-chevron">&#9654;</span>
          <span class="access-dot ro"></span>
          <span>Sandbox Preferences</span>
        </div>
        <span class="source-pill">&#8984; preferences</span>
      </summary>
      <div class="app-fold-body">
        ${defaultModeControlHtml}
        ${idleControlHtml}
        ${worktreeModeRowHtml}
      </div>
    </details>

    <details class="app-fold" data-section="settings-delegation" ${isSectionOpen('settings-delegation', true) ? 'open' : ''}>
      <summary>
        <div style="display:flex;align-items:center;gap:8px;">
          <span class="fold-chevron">&#9654;</span>
          <span class="access-dot l7"></span>
          <span>Delegation &amp; Orchestration</span>
        </div>
        <span class="source-pill">&#8984; broker</span>
      </summary>
      <div class="app-fold-body">
        ${delegationRowsHtml}
      </div>
    </details>

    <details class="app-fold" data-section="settings-paths" ${isSectionOpen('settings-paths', true) ? 'open' : ''}>
      <summary>
        <div style="display:flex;align-items:center;gap:8px;">
          <span class="fold-chevron">&#9654;</span>
          <span class="access-dot rw"></span>
          <span>Configuration Paths</span>
        </div>
        <span class="source-pill">&#8984; files</span>
      </summary>
      <div class="app-fold-body">
        ${pathsHtml}
      </div>
    </details>
  `
}
