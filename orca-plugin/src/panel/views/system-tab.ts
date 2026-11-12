import { panelState } from '../state.ts'
import { escapeHtml } from '../utils.ts'

function describeMountPath(
  mountPath: string,
  access: string,
  wsName: string,
  agentName: string
): { source: string; explanation: string; sourceFile: string } {
  if (mountPath === `/sandbox/${wsName}`) {
    return {
      source: 'workspace',
      explanation: 'Project worktree mounted read-write inside the sandbox.',
      sourceFile: `${agentName}.json`,
    }
  }
  if (mountPath.startsWith('/sandbox/.')) {
    return {
      source: `${agentName}-state`,
      explanation: 'Agent state & configuration directory mounted read-write across turns.',
      sourceFile: `${agentName}.json`,
    }
  }
  if (mountPath === '/tmp' || mountPath.startsWith('/tmp/')) {
    return {
      source: 'temp-fs',
      explanation: 'Ephemeral scratch directory inside the sandbox.',
      sourceFile: `${agentName}.json`,
    }
  }
  return {
    source: access === 'read-write' ? 'fs-rw' : 'system-ro',
    explanation:
      access === 'read-write'
        ? 'Writable Landlock filesystem path.'
        : 'Read-only system path required to execute standard CLI tools and runtimes.',
    sourceFile: `${agentName}.json`,
  }
}

export function renderSystemTab(): string {
  const report = panelState.currentReport
  if (!report) return ''

  const a = report.agents[0]
  if (!a) {
    return `<div class="card"><div class="sub">No agent profile found.</div></div>`
  }
  const wsName = report.selectedWorkspace.name

  const fsEntries = [
    ...a.filesystemReadWrite.map(p => ({ path: p, access: 'read-write', dot: 'rw' })),
    ...a.filesystemReadOnly.map(p => ({ path: p, access: 'read-only', dot: 'ro' })),
  ]

  const fsCardsHtml = fsEntries
    .map(item => {
      const info = describeMountPath(item.path, item.access, wsName, a.agent)
      const tooltip = `Landlock (${item.access}) • ${info.sourceFile}\n${info.explanation}`
      return `
        <div class="cmd-row" data-tooltip="${escapeHtml(tooltip)}">
          <div style="display:flex;align-items:center;gap:8px;min-width:0;flex:1;">
            <span class="access-dot ${item.dot}"></span>
            <span class="cmd-code" style="font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${escapeHtml(item.path)}</span>
          </div>
          <div style="display:flex;align-items:center;gap:6px;flex-shrink:0;">
            <span class="source-pill" data-tooltip="${escapeHtml(tooltip)}">&#8984; ${escapeHtml(info.source)}</span>
          </div>
        </div>
      `
    })
    .join('')

  const envCardsHtml = a.credentialPlaceholders
    .map(envKey => {
      const tooltip = `openshell:resolve • ${a.providerProfile}.profile.yaml\nProxy-injected credential placeholder (never readable in plain text inside the sandbox).`
      return `
        <div class="cmd-row" data-tooltip="${escapeHtml(tooltip)}">
          <div style="display:flex;align-items:center;gap:8px;min-width:0;flex:1;">
            <span class="access-dot l7"></span>
            <span class="cmd-code" style="font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${escapeHtml(envKey)}</span>
          </div>
          <div style="display:flex;align-items:center;gap:6px;flex-shrink:0;">
            <span class="source-pill" data-tooltip="${escapeHtml(tooltip)}">&#8984; openshell:resolve</span>
          </div>
        </div>
      `
    })
    .join('')

  const binCardsHtml = a.allowedBinaries
    .map(binPath => {
      const baseName = binPath.split('/').pop() || binPath
      const tooltip = `Executable container binary inside ${a.containerImage} (${a.hostWrapper})`
      return `
        <div class="cmd-row" data-tooltip="${escapeHtml(tooltip)}">
          <div style="display:flex;align-items:center;gap:8px;min-width:0;flex:1;">
            <span class="access-dot ro"></span>
            <span class="cmd-code" style="font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${escapeHtml(binPath)}</span>
          </div>
          <div style="display:flex;align-items:center;gap:6px;flex-shrink:0;">
            <span class="source-pill" data-tooltip="${escapeHtml(tooltip)}">&#8984; ${escapeHtml(baseName)}</span>
          </div>
        </div>
      `
    })
    .join('')

  const currentSb = (report.activeSandboxes || [])[0] || null
  const isCurrentSbStopped = Boolean(currentSb && /stopped/i.test(currentSb.phase || ''))
  const isCurrentSbReady = Boolean(currentSb && /ready|running/i.test(currentSb.phase || ''))
  const defaultEnabled = report.defaultSandboxEnabled === true
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

  const currentSbCardHtml = currentSb
    ? (() => {
        const sbDot = isCurrentSbReady ? 'rw' : isCurrentSbStopped ? 'ro' : 'l7'
        const phaseLabel = isCurrentSbStopped ? 'Paused' : currentSb.phase || 'Active'
        const actionBtnHtml = isCurrentSbStopped
          ? `<button class="copy-btn primary resume-sb-btn" data-sandbox="${escapeHtml(currentSb.name)}" title="Restart paused OpenShell sandbox container">Resume</button>`
          : `<button class="copy-btn pause-sb-btn" data-sandbox="${escapeHtml(currentSb.name)}" title="Stop sandbox container when idle while preserving /sandbox and L7 policies">Pause</button>`
        return `
          <div class="cmd-row">
            <div style="display:flex;align-items:center;gap:8px;min-width:0;flex:1;">
              <span class="access-dot ${sbDot}" title="Phase: ${escapeHtml(currentSb.phase)}"></span>
              <span class="cmd-code" style="font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${escapeHtml(currentSb.name)}</span>
            </div>
            <div style="display:flex;align-items:center;gap:6px;flex-shrink:0;">
              <span class="source-pill">${escapeHtml(phaseLabel)}</span>
              ${actionBtnHtml}
              <button class="copy-btn stop-sb-btn" data-sandbox="${escapeHtml(currentSb.name)}" title="Permanently delete OpenShell sandbox container">Delete</button>
            </div>
          </div>
        `
      })()
    : `<div class="sub">No sandbox container running for this tab yet.</div>`

  const docReport = panelState.doctorReport
  const docChecksHtml = docReport
    ? `<div style="display:flex;flex-direction:column;gap:4px;padding:6px 8px;background:var(--bg-elev);border:1px solid var(--border);border-radius:6px;">
        ${docReport.checks
          .map(c => {
            const dot = c.status === 'pass' ? 'rw' : c.status === 'warn' ? 'l7' : 'deny'
            return `<div class="cmd-meta" style="align-items:center;justify-content:space-between;gap:8px;">
              <div style="display:flex;align-items:center;gap:6px;min-width:0;">
                <span class="access-dot ${dot}" title="${escapeHtml(c.status)}"></span>
                <strong style="color:var(--fg);white-space:nowrap;">${escapeHtml(c.label)}:</strong>
                <span class="sub" style="overflow:hidden;text-overflow:ellipsis;">${escapeHtml(c.detail)}</span>
              </div>
              <span class="badge ${c.status === 'pass' ? 'allow' : c.status === 'warn' ? 'warn' : 'deny'}">${escapeHtml(c.status.toUpperCase())}</span>
            </div>`
          })
          .join('')}
      </div>`
    : ''

  const doctorControlHtml = `
    <div class="cmd-row" style="justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap;">
      <div style="display:flex;flex-direction:column;gap:2px;min-width:0;flex:1;">
        <span style="font-size:11px;font-weight:600;color:var(--fg);">System Health &amp; Registry</span>
        <span class="sub">Verifies OpenShell gateway, host wrappers, base L7 policies, and reconciles stale session entries.</span>
      </div>
      <button id="runDoctorBtn" class="copy-btn" ${panelState.runningDoctor ? 'disabled' : ''} title="Run OpenShell environment diagnostics and prune stale registry entries">
        ${panelState.runningDoctor ? 'Checking...' : 'Run Doctor'}
      </button>
    </div>
    ${docChecksHtml}
  `

  return `
    <details class="app-fold" data-section="sys-sb" open>
      <summary>
        <div style="display:flex;align-items:center;gap:8px;">
          <span class="fold-chevron">&#9654;</span>
          <span class="access-dot ${isCurrentSbReady ? 'rw' : 'ro'}"></span>
          <span>Current Sandbox</span>
        </div>
        <span class="source-pill">&#8984; ${escapeHtml(currentSb ? currentSb.name : 'idle')}</span>
      </summary>
      <div class="app-fold-body">
        ${currentSbCardHtml}
        ${defaultModeControlHtml}
        ${idleControlHtml}
        ${doctorControlHtml}
      </div>
    </details>

    <details class="app-fold" data-section="sys-fs" ${panelState.openSections.has('sys-fs') || !panelState.openSections.has('sys-fs-closed') ? 'open' : ''}>
      <summary>
        <div style="display:flex;align-items:center;gap:8px;">
          <span class="fold-chevron">&#9654;</span>
          <span class="access-dot rw"></span>
          <span>Filesystem (${fsEntries.length})</span>
        </div>
        <span class="source-pill">&#8984; landlock</span>
      </summary>
      <div class="app-fold-body">
        ${fsCardsHtml}
      </div>
    </details>

    <details class="app-fold" data-section="sys-vars" ${panelState.openSections.has('sys-vars') || !panelState.openSections.has('sys-vars-closed') ? 'open' : ''}>
      <summary>
        <div style="display:flex;align-items:center;gap:8px;">
          <span class="fold-chevron">&#9654;</span>
          <span class="access-dot l7"></span>
          <span>Variables &amp; Binaries (${a.credentialPlaceholders.length + a.allowedBinaries.length})</span>
        </div>
        <span class="source-pill">&#8984; ${escapeHtml(a.providerProfile)}</span>
      </summary>
      <div class="app-fold-body">
        ${envCardsHtml}
        ${binCardsHtml}
      </div>
    </details>
  `
}
