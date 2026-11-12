import type {
  AddL7PolicyRequest,
  AddL7PolicyResult,
  CommandEvaluationResult,
  PolicyInspectionReport,
} from '../types.ts'
import { panelState, type PanelTab } from './state.ts'
import { copyText, endpointsSignature, escapeHtml, sandboxesSignature } from './utils.ts'
import { renderCliTab } from './views/cli-tab.ts'
import { renderEgressTab } from './views/egress-tab.ts'
import { renderSystemTab } from './views/system-tab.ts'

function getInputValue(id: string): string {
  const el = document.getElementById(id) as HTMLInputElement | HTMLSelectElement | null
  return el ? el.value : ''
}

function renderHeader(): void {
  const report = panelState.currentReport
  if (!report) return

  const ws = report.selectedWorkspace
  const sbEnabled = report.sandboxEnabled !== false
  const inheritedFrom = report.sandboxInheritedFrom || null
  const parentLabel = inheritedFrom
    ? inheritedFrom.split('/').filter(Boolean).pop() || inheritedFrom
    : ''
  const currentSb = (report.activeSandboxes || [])[0] || null
  const isPausedSb = Boolean(currentSb && /stopped/i.test(currentSb.phase || ''))
  const runningCount = currentSb && !isPausedSb ? 1 : 0
  const pausedCount = currentSb && isPausedSb ? 1 : 0
  const badge = document.getElementById('sandboxBadge')
  if (badge) {
    if (!sbEnabled) {
      badge.className = 'badge warn'
      badge.textContent = inheritedFrom ? 'Off (Parent)' : 'Off (Host)'
      badge.title = 'OpenShell sandboxing deactivated for this worktree'
    } else if (runningCount > 0 && currentSb) {
      badge.className = 'badge allow'
      badge.textContent = 'Running'
      badge.title = `Current tab sandbox: ${currentSb.name} (${currentSb.phase || 'Ready'})`
    } else if (pausedCount > 0 && currentSb) {
      badge.className = 'badge neutral'
      badge.textContent = 'Paused'
      badge.title = `Current tab sandbox: ${currentSb.name} (Paused)`
    } else {
      badge.className = 'badge neutral'
      badge.textContent = 'Enforced'
      badge.title = 'No sandbox container running for this tab yet'
    }
  }

  const toggleBtn = document.getElementById('sandboxToggleBtn') as HTMLButtonElement | null
  if (toggleBtn) {
    toggleBtn.setAttribute('aria-checked', sbEnabled ? 'true' : 'false')
    toggleBtn.title = inheritedFrom
      ? `Sandbox mode for ${ws.name} (currently inherited from ${parentLabel})`
      : `Activate or deactivate OpenShell sandboxing for ${ws.name} and its child workspaces`
  }

  const bypassNotice = document.getElementById('bypassNotice')
  const bypassNoticeText = document.getElementById('bypassNoticeText')
  if (bypassNotice) {
    bypassNotice.style.display = sbEnabled ? 'none' : 'flex'
  }
  if (bypassNoticeText && !sbEnabled) {
    bypassNoticeText.textContent = inheritedFrom
      ? `Sandboxing deactivated for ${ws.name} (inherited from ${parentLabel}) \u2014 new agent tabs & chat commands run directly on host.`
      : `Sandboxing deactivated for ${ws.name} \u2014 new agent tabs & chat commands run directly on host.`
  }

  const projLabel = document.getElementById('projectLabel')
  if (projLabel) projLabel.textContent = ws.name
  const projBox = document.getElementById('projectStatBox')
  if (projBox) projBox.title = ws.path
  const branchBadge = document.getElementById('branchBadge')
  if (branchBadge) branchBadge.textContent = ws.branch || 'main'

  const agentObj = report.agents[0]
  const activeSession = (report.activeAgentSessions || [])[0]
  const agentDisplay = agentObj ? agentObj.displayName : report.currentAgent
  const agentLabel = document.getElementById('agentLabel')
  if (agentLabel) agentLabel.textContent = agentDisplay

  const stateBadge = document.getElementById('agentStateBadge')
  if (stateBadge) {
    const sessionState = activeSession
      ? activeSession.state
      : runningCount > 0
        ? 'sandboxed'
        : pausedCount > 0
          ? 'paused'
          : 'ready'
    stateBadge.textContent = sessionState.toUpperCase()
    stateBadge.className =
      'badge ' +
      (sessionState === 'working' || sessionState === 'running' || runningCount > 0
        ? 'allow'
        : 'neutral')
  }

  const agentRules = report.allCliRules.filter(r =>
    r.compatibleAgents.includes(report.currentAgent)
  )
  const cliCount = document.getElementById('cliCount')
  if (cliCount) cliCount.textContent = String(agentRules.length)
  const egressCountEl = document.getElementById('egressCount')
  if (egressCountEl) {
    egressCountEl.textContent = String(agentObj?.endpoints?.length || 0)
  }
}

async function applyL7PolicyRule(
  payload: Partial<AddL7PolicyRequest>,
  statusElId: string
): Promise<void> {
  const statusEl = statusElId ? document.getElementById(statusElId) : null
  if (statusEl) {
    statusEl.style.display = 'flex'
    statusEl.innerHTML = `<span class="badge neutral">Applying L7 policy...</span>`
  }
  try {
    const report = panelState.currentReport
    const currentSbName = report?.activeSandboxes?.[0]?.name
    const res = (await window.orca.plugin.request('addL7Policy', {
      ...payload,
      ...(payload?.scope === 'session' && currentSbName ? { sandboxName: currentSbName } : {}),
      workspacePath: report?.selectedWorkspace?.path,
      agent: report?.currentAgent,
    })) as AddL7PolicyResult

    if (statusEl) {
      const cmdsHtml = (res.cliCommandsRun || [])
        .map(c => `<div class="mono sub">$ ${escapeHtml(c)}</div>`)
        .join('')
      statusEl.innerHTML = `
        <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;">
          <span class="badge ${res.ok ? 'allow' : 'deny'}">${res.ok ? 'APPLIED' : 'ERROR'}</span>
          <span>${escapeHtml(res.message)}</span>
        </div>
        ${cmdsHtml}
      `
    }
    if (res.ok) {
      const reportRes = (await window.orca.plugin.request(
        'getPolicyReport',
        {}
      )) as PolicyInspectionReport
      panelState.currentReport = reportRes
      renderHeader()
      renderActiveTab()
      const cmd = getInputValue('cmdInput').trim()
      if (cmd) await runCommandCheck(cmd, true)
    }
  } catch (err: any) {
    if (statusEl) {
      statusEl.innerHTML = `<span class="badge deny">Error</span><div>${escapeHtml(err?.message || err)}</div>`
    }
  }
}

async function runCommandCheck(
  command: string,
  execute = false,
  forceExecute = false
): Promise<void> {
  const report = panelState.currentReport
  const trimmed = command.trim()
  if (!trimmed || !report) return
  const box = document.getElementById('evalOutput')
  if (!box) return

  const testBtn = document.getElementById('testBtn') as HTMLButtonElement | null
  const runCmdBtn = document.getElementById('runCmdBtn') as HTMLButtonElement | null
  if (execute) {
    box.style.display = 'flex'
    const targetLabel =
      report.sandboxEnabled !== false
        ? `OpenShell Sandbox (${report.activeSandboxes?.[0]?.name || report.selectedWorkspace.name})`
        : `Host (${report.selectedWorkspace.name})`
    box.innerHTML = `<div style="display:flex;align-items:center;gap:8px;"><span class="badge neutral">Running...</span><span class="sub">Executing <code class="mono">${escapeHtml(trimmed)}</code> in ${escapeHtml(targetLabel)}...</span></div>`
    if (testBtn) testBtn.disabled = true
    if (runCmdBtn) runCmdBtn.disabled = true
  }

  try {
    const res = (await window.orca.plugin.request('evaluateCommand', {
      command: trimmed,
      workspacePath: report.selectedWorkspace.path,
      agent: report.currentAgent,
      execute,
      forceExecute,
    })) as CommandEvaluationResult
    panelState.lastL7Suggestion = res.l7Suggestion || null
    box.style.display = 'flex'
    const dotClassForAction = (act: string) =>
      act === 'allow' || act === 'pass' ? 'rw' : act === 'ask' || act === 'warn' ? 'l7' : 'deny'
    const verdictDot = dotClassForAction(res.verdict)
    const rulesHtml = (res.matchedRules || [])
      .map(r => {
        const rDot = dotClassForAction(r.action)
        return `<div class="cmd-meta" style="align-items:center;"><span class="access-dot ${rDot}" title="Rule: ${escapeHtml(r.action)}"></span><span class="mono" style="color:var(--fg);font-weight:600;">${escapeHtml(r.cliCommand)}</span><span class="source-pill" title="Source: ${escapeHtml(r.sourceFile)}">&#8984; ${escapeHtml(r.groupName)}</span></div>`
      })
      .join('')
    const checksHtml = (res.sandboxChecks || [])
      .map(c => {
        const cDot = dotClassForAction(c.status)
        return `<div class="cmd-meta" style="align-items:center;"><span class="access-dot ${cDot}" title="${escapeHtml(c.layer)}: ${escapeHtml(c.status)}"></span><strong style="color:var(--fg);">${escapeHtml(c.layer)}:</strong><span>${escapeHtml(c.detail)}</span></div>`
      })
      .join('')
    const l7ActionHtml = res.l7Suggestion
      ? `<div style="margin-top:4px;padding-top:6px;border-top:1px solid var(--border);display:flex;flex-direction:column;gap:6px;">
          <div class="cmd-meta" style="align-items:center;">
            <span class="access-dot l7" title="L7 HTTP Rule"></span>
            <strong style="color:var(--fg);">L7 HTTP Rule:</strong>
            <code class="mono">${escapeHtml(res.l7Suggestion.action.toUpperCase())} ${escapeHtml(res.l7Suggestion.method)} https://${escapeHtml(res.l7Suggestion.host)}:${res.l7Suggestion.port}${escapeHtml(res.l7Suggestion.path)}</code>
            <span class="source-pill">&#8984; ${escapeHtml(res.l7Suggestion.binary)}</span>
          </div>
          <div style="display:flex;gap:6px;flex-wrap:wrap;">
            <button class="copy-btn quick-l7-btn" data-l7-scope="session" title="Allow for this session only and tag Temporary in Sandbox Egress">Allow Temporarily</button>
            <button class="copy-btn primary quick-l7-btn" data-l7-scope="workspace" title="Save to project rules (.agents/policies/l7-custom.json) &amp; apply live">Allow (Project)</button>
            <button class="copy-btn quick-l7-btn" data-l7-scope="global" title="Save to ~/.agents/orca-openshell-policies/${escapeHtml(report.currentAgent)}.json &amp; apply live">Allow Global</button>
          </div>
          <div id="quickL7Status" style="display:none;" class="eval-result"></div>
        </div>`
      : ''

    let execHtml = ''
    if (res.execution) {
      if (!res.execution.executed) {
        execHtml = `<div style="margin-top:4px;padding-top:6px;border-top:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap;">
          <span class="sub">${escapeHtml(res.execution.skippedReason || 'Execution skipped.')}</span>
          <button class="copy-btn force-run-cmd-btn" data-cmd="${escapeHtml(res.command)}">Run Anyway</button>
        </div>`
      } else {
        const outParts = [res.execution.stdout.trimEnd(), res.execution.stderr.trimEnd()].filter(
          Boolean
        )
        const combinedOutput = outParts.join('\n')
        const exitBadgeClass = res.execution.exitCode === 0 ? 'allow' : 'deny'
        const targetText =
          res.execution.target === 'sandbox'
            ? `Sandbox${res.execution.sandboxName ? `: ${res.execution.sandboxName}` : ''}`
            : `Host: ${report.selectedWorkspace.name}`
        const copyBtnHtml = combinedOutput
          ? `<button class="copy-btn" data-copy="${escapeHtml(combinedOutput)}">Copy Output</button>`
          : ''
        execHtml = `<div style="margin-top:4px;padding-top:6px;border-top:1px solid var(--border);display:flex;flex-direction:column;gap:6px;">
          <div style="display:flex;align-items:center;justify-content:space-between;gap:6px;flex-wrap:wrap;">
            <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;">
              <strong style="font-size:11px;color:var(--fg);">Output</strong>
              <span class="badge neutral" title="Working directory: ${escapeHtml(res.execution.cwd)}">${escapeHtml(targetText)}</span>
              <span class="badge ${exitBadgeClass}">Exit ${escapeHtml(String(res.execution.exitCode ?? 0))}</span>
              <span class="sub">${escapeHtml(String(res.execution.durationMs))}ms</span>
            </div>
            ${copyBtnHtml}
          </div>
          <pre class="mono cmd-output-pre">${escapeHtml(combinedOutput || '(no output)')}</pre>
        </div>`
      }
    }

    box.innerHTML = `
      <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap;">
        <div style="display:flex;align-items:center;gap:7px;min-width:0;">
          <span class="access-dot ${verdictDot}" title="Verdict: ${escapeHtml(res.verdict)}"></span>
          <span class="mono" style="font-weight:600;color:var(--fg);">${escapeHtml(res.command)}</span>
        </div>
        <span class="source-pill">${escapeHtml(res.verdict.toUpperCase())}</span>
      </div>
      <div class="sub">${escapeHtml(res.summary)}</div>
      ${rulesHtml}
      ${checksHtml}
      ${l7ActionHtml}
      ${execHtml}
    `
  } catch (err: any) {
    box.style.display = 'flex'
    box.innerHTML = `<div style="display:flex;align-items:center;gap:6px;"><span class="access-dot deny"></span><div>${escapeHtml(err?.message || err)}</div></div>`
  } finally {
    if (testBtn) testBtn.disabled = false
    if (runCmdBtn) runCmdBtn.disabled = false
  }
}

async function loadReport(): Promise<void> {
  try {
    const res = (await window.orca.plugin.request('getPolicyReport', {})) as PolicyInspectionReport
    const prev = panelState.currentReport
    const changedContext =
      !prev ||
      prev.sandboxEnabled !== res.sandboxEnabled ||
      prev.defaultSandboxEnabled !== res.defaultSandboxEnabled ||
      prev.sandboxIdleTimeoutSeconds !== res.sandboxIdleTimeoutSeconds ||
      prev.selectedWorkspace.path !== res.selectedWorkspace.path ||
      prev.currentAgent !== res.currentAgent ||
      sandboxesSignature(prev) !== sandboxesSignature(res) ||
      endpointsSignature(prev) !== endpointsSignature(res)

    panelState.currentReport = res
    renderHeader()
    const activeElId = document.activeElement?.id || ''
    const isTypingInFilter = activeElId === 'ruleSearch' || activeElId === 'egressSearch'
    if (
      (changedContext && !isTypingInFilter) ||
      (!document.getElementById('ruleSearch') &&
        !document.getElementById('egressSearch') &&
        panelState.activeTab !== 'system')
    ) {
      renderActiveTab()
    }
    const cmd = getInputValue('cmdInput').trim()
    if (cmd && changedContext) await runCommandCheck(cmd)
  } catch (err: any) {
    const container = document.getElementById('tabContent')
    if (container) {
      container.innerHTML = `<div class="card"><span class="badge deny">Error</span><div class="mono">${escapeHtml(err?.message || err)}</div></div>`
    }
  }
}

async function toggleSandboxMode(): Promise<void> {
  const report = panelState.currentReport
  if (!report || panelState.togglingSandbox) return
  panelState.togglingSandbox = true
  const nextEnabled = report.sandboxEnabled === false
  const toggleBtn = document.getElementById('sandboxToggleBtn') as HTMLButtonElement | null
  if (toggleBtn) toggleBtn.disabled = true
  try {
    const res = (await window.orca.plugin.request('setSandboxMode', {
      enabled: nextEnabled,
      workspacePath: report.selectedWorkspace?.path,
      workspaceId: report.selectedWorkspace?.id,
      agent: report.currentAgent,
    })) as PolicyInspectionReport
    panelState.currentReport = res
    renderHeader()
    renderActiveTab()
    const cmd = getInputValue('cmdInput').trim()
    if (cmd) await runCommandCheck(cmd)
  } catch {} finally {
    panelState.togglingSandbox = false
    if (toggleBtn) toggleBtn.disabled = false
  }
}

function renderActiveTab(): void {
  if (!panelState.currentReport) return
  const container = document.getElementById('tabContent')
  if (!container) return

  if (panelState.activeTab === 'cli') container.innerHTML = renderCliTab()
  else if (panelState.activeTab === 'egress') container.innerHTML = renderEgressTab()
  else container.innerHTML = renderSystemTab()

  const defaultSandboxModeSelect = document.getElementById(
    'defaultSandboxModeSelect'
  ) as HTMLSelectElement | null
  if (defaultSandboxModeSelect) {
    defaultSandboxModeSelect.addEventListener('change', async e => {
      const enabled = (e.target as HTMLSelectElement).value === 'on'
      defaultSandboxModeSelect.disabled = true
      try {
        const report = panelState.currentReport
        const res = (await window.orca.plugin.request('setDefaultSandboxMode', {
          enabled,
          workspacePath: report?.selectedWorkspace?.path,
          agent: report?.currentAgent,
        })) as PolicyInspectionReport | null
        if (res) {
          panelState.currentReport = res
          renderHeader()
          renderActiveTab()
        }
      } catch {} finally {
        defaultSandboxModeSelect.disabled = false
      }
    })
  }

  const idleTimeoutSelect = document.getElementById('idleTimeoutSelect') as HTMLSelectElement | null
  if (idleTimeoutSelect) {
    idleTimeoutSelect.addEventListener('change', async e => {
      const seconds = Number((e.target as HTMLSelectElement).value)
      idleTimeoutSelect.disabled = true
      try {
        const report = panelState.currentReport
        const res = (await window.orca.plugin.request('setSandboxIdleTimeout', {
          seconds,
          sandboxName: report?.activeSandboxes?.[0]?.name,
          paneKey: report?.activeAgentSessions?.[0]?.paneKey,
          workspacePath: report?.selectedWorkspace?.path,
          agent: report?.currentAgent,
        })) as PolicyInspectionReport | null
        if (res) {
          panelState.currentReport = res
          renderHeader()
          renderActiveTab()
        }
      } catch {} finally {
        idleTimeoutSelect.disabled = false
      }
    })
  }

  const runDoctorBtn = document.getElementById('runDoctorBtn') as HTMLButtonElement | null
  if (runDoctorBtn) {
    runDoctorBtn.addEventListener('click', async () => {
      if (panelState.runningDoctor) return
      panelState.runningDoctor = true
      renderActiveTab()
      try {
        const report = panelState.currentReport
        const res = (await window.orca.plugin.request('runDoctor', {
          workspacePath: report?.selectedWorkspace?.path,
          agent: report?.currentAgent,
        })) as { doctor?: any; report?: PolicyInspectionReport } | null
        if (res?.doctor) {
          panelState.doctorReport = res.doctor
        }
        if (res?.report) {
          panelState.currentReport = res.report
          renderHeader()
        }
      } catch {} finally {
        panelState.runningDoctor = false
        renderActiveTab()
      }
    })
  }

  container.querySelectorAll<HTMLDetailsElement>('details.app-fold').forEach(el => {
    el.addEventListener('toggle', () => {
      const app = el.dataset.app
      if (app) {
        if (el.open) panelState.openApps.add(app)
        else panelState.openApps.delete(app)
      }
      const sec = el.dataset.section
      if (sec) {
        if (el.open) panelState.openSections.add(sec)
        else panelState.openSections.delete(sec)
      }
    })
  })

  container.querySelectorAll<HTMLDetailsElement>('details.egress-fold').forEach(el => {
    el.addEventListener('toggle', () => {
      const key = el.dataset.egress
      if (key) {
        if (el.open) panelState.openEgress.add(key)
        else panelState.openEgress.delete(key)
      }
      const cliRule = el.dataset.cliRule
      if (cliRule) {
        if (el.open) panelState.openCliRules.add(cliRule)
        else panelState.openCliRules.delete(cliRule)
      }
      const sysItem = el.dataset.sysItem
      if (sysItem) {
        if (el.open) panelState.openSystemItems.add(sysItem)
        else panelState.openSystemItems.delete(sysItem)
      }
    })
  })

  document.getElementById('expandEgressBtn')?.addEventListener('click', () => {
    container.querySelectorAll<HTMLDetailsElement>('details.egress-fold').forEach(el => {
      el.open = true
      if (el.dataset.egress) panelState.openEgress.add(el.dataset.egress)
    })
  })

  document.getElementById('collapseEgressBtn')?.addEventListener('click', () => {
    panelState.openEgress.clear()
    container.querySelectorAll<HTMLDetailsElement>('details.egress-fold').forEach(el => {
      el.open = false
    })
  })

  document.getElementById('egressSearch')?.addEventListener('input', e => {
    panelState.egressSearch = (e.target as HTMLInputElement).value
    renderActiveTab()
    const input = document.getElementById('egressSearch') as HTMLInputElement | null
    if (input) {
      input.focus()
      input.setSelectionRange(input.value.length, input.value.length)
    }
  })

  document.getElementById('expandAllBtn')?.addEventListener('click', () => {
    container.querySelectorAll<HTMLDetailsElement>('details.app-fold').forEach(el => {
      el.open = true
      if (el.dataset.app) panelState.openApps.add(el.dataset.app)
    })
  })

  document.getElementById('collapseAllBtn')?.addEventListener('click', () => {
    panelState.openApps.clear()
    container.querySelectorAll<HTMLDetailsElement>('details.app-fold').forEach(el => {
      el.open = false
    })
  })

  document.getElementById('addL7Btn')?.addEventListener('click', () => {
    const scope = getInputValue('l7Scope') as 'session' | 'workspace' | 'global'
    const action = getInputValue('l7Action') as 'allow' | 'deny'
    const method = getInputValue('l7Method')
    const host = getInputValue('l7Host').trim()
    const port = Number(getInputValue('l7Port')) || 443
    const path = getInputValue('l7Path').trim() || '/**'
    const binary = getInputValue('l7Binary').trim() || '*'
    const triggerCommand = getInputValue('l7TriggerCmd').trim()
    panelState.openSections.add('l7-composer')
    void applyL7PolicyRule(
      { scope, action, method, host, port, path, binary, triggerCommand },
      'l7ComposerStatus'
    )
  })

  document.getElementById('ruleSearch')?.addEventListener('input', e => {
    panelState.searchFilter = (e.target as HTMLInputElement).value
    renderActiveTab()
    const input = document.getElementById('ruleSearch') as HTMLInputElement | null
    if (input) {
      input.focus()
      input.setSelectionRange(input.value.length, input.value.length)
    }
  })

  document.getElementById('actionSelect')?.addEventListener('change', e => {
    panelState.actionFilter = (e.target as HTMLSelectElement).value
    renderActiveTab()
  })
}

function bootstrapPanel(): void {
  document.addEventListener('click', e => {
    const target = e.target
    if (!(target instanceof HTMLElement)) return
    const report = panelState.currentReport

    if (target.dataset.copy) {
      void copyText(target.dataset.copy, target)
    } else if (target.classList.contains('pause-sb-btn')) {
      const btn = target as HTMLButtonElement
      const sbName = btn.dataset.sandbox || ''
      if (sbName) {
        btn.disabled = true
        btn.textContent = 'Pausing...'
        window.orca.plugin
          .request('pauseSandbox', {
            sandboxName: sbName,
            workspacePath: report?.selectedWorkspace?.path,
            agent: report?.currentAgent,
          })
          .then((res: any) => {
            if (res?.report) {
              panelState.currentReport = res.report
              renderHeader()
              renderActiveTab()
            } else {
              void loadReport()
            }
          })
          .catch(() => {
            btn.disabled = false
            btn.textContent = 'Pause'
          })
      }
    } else if (target.classList.contains('resume-sb-btn')) {
      const btn = target as HTMLButtonElement
      const sbName = btn.dataset.sandbox || ''
      if (sbName) {
        btn.disabled = true
        btn.textContent = 'Resuming...'
        window.orca.plugin
          .request('resumeSandbox', {
            sandboxName: sbName,
            workspacePath: report?.selectedWorkspace?.path,
            agent: report?.currentAgent,
          })
          .then((res: any) => {
            if (res?.report) {
              panelState.currentReport = res.report
              renderHeader()
              renderActiveTab()
            } else {
              void loadReport()
            }
          })
          .catch(() => {
            btn.disabled = false
            btn.textContent = 'Resume'
          })
      }
    } else if (target.classList.contains('stop-sb-btn')) {
      const btn = target as HTMLButtonElement
      const sbName = btn.dataset.sandbox || ''
      if (sbName) {
        btn.disabled = true
        btn.textContent = 'Deleting...'
        window.orca.plugin
          .request('stopSandbox', {
            sandboxName: sbName,
            workspacePath: report?.selectedWorkspace?.path,
            agent: report?.currentAgent,
          })
          .then((res: any) => {
            if (res?.report) {
              panelState.currentReport = res.report
              renderHeader()
              renderActiveTab()
            } else {
              void loadReport()
            }
          })
          .catch(() => {
            btn.disabled = false
            btn.textContent = 'Delete'
          })
      }
    } else if (target.classList.contains('promote-temp-btn')) {
      const btn = target as HTMLButtonElement
      const host = btn.dataset.host || ''
      const port = Number(btn.dataset.port || '443')
      const action = (btn.dataset.action || 'allow') as 'allow' | 'deny'
      const method = btn.dataset.method || 'GET'
      const path = btn.dataset.path || '/**'
      if (host) {
        btn.disabled = true
        btn.textContent = 'Saving...'
        void applyL7PolicyRule({ scope: 'workspace', host, port, action, method, path, binary: '*' }, '')
      }
    } else if (target.classList.contains('remove-temp-btn')) {
      const btn = target as HTMLButtonElement
      const host = btn.dataset.host || ''
      const port = Number(btn.dataset.port || '443')
      if (host) {
        btn.disabled = true
        window.orca.plugin
          .request('removeTemporaryL7Rule', {
            sandboxName: report?.activeSandboxes?.[0]?.name,
            host,
            port,
            workspacePath: report?.selectedWorkspace?.path,
            agent: report?.currentAgent,
          })
          .then((res: any) => {
            if (res?.report) {
              panelState.currentReport = res.report
              renderHeader()
              renderActiveTab()
            } else {
              void loadReport()
            }
          })
          .catch(() => {
            btn.disabled = false
          })
      }
    } else if (target.classList.contains('quick-l7-btn') && panelState.lastL7Suggestion) {
      const scope = (target.dataset.l7Scope || 'workspace') as 'session' | 'workspace' | 'global'
      void applyL7PolicyRule({ ...panelState.lastL7Suggestion, scope }, 'quickL7Status')
    } else if (target.classList.contains('force-run-cmd-btn')) {
      const cmd = target.dataset.cmd || getInputValue('cmdInput')
      if (cmd) void runCommandCheck(cmd, true, true)
    } else if (target.classList.contains('sample-cmd')) {
      const cmd = target.dataset.cmd || ''
      const cmdInput = document.getElementById('cmdInput') as HTMLInputElement | null
      if (cmdInput) cmdInput.value = cmd
      void runCommandCheck(cmd, false)
    } else if (target.classList.contains('tab')) {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'))
      target.classList.add('active')
      panelState.activeTab = (target.dataset.tab || 'cli') as PanelTab
      renderActiveTab()
    }
  })

  document.getElementById('sandboxToggleBtn')?.addEventListener('click', () => {
    void toggleSandboxMode()
  })
  document.getElementById('refreshBtn')?.addEventListener('click', () => {
    void loadReport()
  })
  document.getElementById('testBtn')?.addEventListener('click', () => {
    void runCommandCheck(getInputValue('cmdInput'), false)
  })
  document.getElementById('runCmdBtn')?.addEventListener('click', () => {
    void runCommandCheck(getInputValue('cmdInput'), true)
  })
  document.getElementById('cmdInput')?.addEventListener('keydown', e => {
    if (e.key === 'Enter') {
      void runCommandCheck((e.target as HTMLInputElement).value, true)
    }
  })

  const tooltipEl = document.getElementById('orcaTooltip')
  const positionTooltip = (clientX: number, clientY: number) => {
    if (!tooltipEl || tooltipEl.style.display === 'none') return
    const pad = 10
    const rect = tooltipEl.getBoundingClientRect()
    let left = clientX + 12
    let top = clientY + 14
    if (left + rect.width > window.innerWidth - pad) {
      left = Math.max(pad, window.innerWidth - rect.width - pad)
    }
    if (top + rect.height > window.innerHeight - pad) {
      top = Math.max(pad, clientY - rect.height - 10)
    }
    tooltipEl.style.left = `${left}px`
    tooltipEl.style.top = `${top}px`
  }

  document.addEventListener('mouseover', e => {
    if (!tooltipEl) return
    const target = e.target
    if (!(target instanceof HTMLElement)) return
    const host = target.closest<HTMLElement>('[data-tooltip]')
    if (!host) {
      tooltipEl.style.display = 'none'
      return
    }
    const text = host.dataset.tooltip?.trim()
    if (!text) {
      tooltipEl.style.display = 'none'
      return
    }
    tooltipEl.textContent = text
    tooltipEl.style.display = 'block'
    positionTooltip(e.clientX, e.clientY)
  })

  document.addEventListener('mousemove', e => {
    positionTooltip(e.clientX, e.clientY)
  })

  document.addEventListener('mouseout', e => {
    if (!tooltipEl) return
    const related = e.relatedTarget
    if (!(related instanceof HTMLElement) || !related.closest('[data-tooltip]')) {
      tooltipEl.style.display = 'none'
    }
  })

  window.addEventListener('scroll', () => {
    if (tooltipEl) tooltipEl.style.display = 'none'
  }, true)

  window.orca?.plugin?.on?.('reportUpdated', (payload: any) => {
    if (payload && typeof payload === 'object' && payload.selectedWorkspace) {
      panelState.currentReport = payload as PolicyInspectionReport
      renderHeader()
      renderActiveTab()
    }
  })

  window.addEventListener('focus', () => {
    void loadReport()
  })
  setInterval(() => {
    if (!document.hidden) void loadReport()
  }, 5000)

  void loadReport()
}

bootstrapPanel()
