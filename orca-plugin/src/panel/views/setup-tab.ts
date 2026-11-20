import { panelState } from '../state.ts'
import { escapeHtml } from '../utils.ts'

function isSectionOpen(sectionId: string, defaultOpen = true): boolean {
  if (defaultOpen) {
    return !panelState.closedSections.has(sectionId)
  }
  return panelState.openSections.has(sectionId)
}

export function renderSetupTab(): string {
  const report = panelState.currentReport
  if (!report) return ''

  const docReport = panelState.doctorReport
  const imgReport = report.sandboxImages
  const setup = report.setup

  const imagesPresentCount = imgReport ? imgReport.images.filter(i => i.present).length : 0
  const imagesTotalCount = imgReport?.images?.length || 4
  const dockerOk = Boolean(imgReport?.dockerAvailable)
  const imagesAllPresent = Boolean(dockerOk && imgReport?.allPresent)

  const wrappers = setup?.wrappers || []
  const wrappersPresentCount = wrappers.filter(w => w.present).length
  const wrappersAllPresent = wrappers.length > 0 && wrappersPresentCount === wrappers.length

  const policies = setup?.policies || []
  const policiesPresentCount = policies.filter(p => p.present).length
  const policiesAllPresent = policies.length > 0 && policiesPresentCount === policies.length

  const cliCheck = docReport?.checks?.find(c => c.id === 'openshell-cli')
  const gatewayCheck = docReport?.checks?.find(c => c.id === 'openshell-cluster')
  const registryCheck = docReport?.checks?.find(c => c.id === 'registry-health')

  const cliOk = cliCheck ? cliCheck.status === 'pass' : Boolean(setup?.openshellInstalled)
  const gatewayOk = gatewayCheck ? gatewayCheck.status === 'pass' : null

  const coreReadyCount = [
    cliOk,
    gatewayOk === true,
    imagesAllPresent,
    wrappersAllPresent,
    policiesAllPresent,
  ].filter(Boolean).length
  const totalCoreChecks = 5

  const hasFailures =
    !cliOk ||
    gatewayOk === false ||
    !imagesAllPresent ||
    !wrappersAllPresent ||
    !policiesAllPresent ||
    Boolean(docReport && !docReport.ok)

  const summaryDot = !hasFailures && gatewayOk === true ? 'rw' : hasFailures ? 'deny' : 'l7'
  const summaryBadgeClass = !hasFailures && gatewayOk === true ? 'allow' : hasFailures ? 'deny' : 'warn'
  const summaryBadgeText =
    !hasFailures && gatewayOk === true
      ? 'ALL READY'
      : panelState.runningDoctor && gatewayOk === null
        ? 'CHECKING...'
        : hasFailures
          ? 'ACTION NEEDED'
          : `${coreReadyCount}/${totalCoreChecks} READY`

  const summarySubtitle =
    !hasFailures && gatewayOk === true
      ? 'OpenShell CLI, Gateway, Docker images, wrappers, and L7 policies are installed and ready.'
      : hasFailures
        ? 'One or more required OpenShell components or container images are missing or unreachable.'
        : 'Checking OpenShell Gateway connectivity and local runtime prerequisites...'

  const summaryBannerHtml = `
    <div class="card" style="padding:9px 10px;gap:7px;">
      <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap;">
        <div style="display:flex;align-items:center;gap:8px;min-width:0;flex:1;">
          <span class="access-dot ${summaryDot}"></span>
          <div style="display:flex;flex-direction:column;gap:1px;min-width:0;">
            <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;">
              <strong style="font-size:12px;color:var(--fg);">Environment Readiness</strong>
              <span class="badge ${summaryBadgeClass}">${summaryBadgeText}</span>
            </div>
            <span class="sub">${escapeHtml(summarySubtitle)}</span>
          </div>
        </div>
        <button id="runDoctorBtn" class="copy-btn primary" ${panelState.runningDoctor ? 'disabled' : ''} title="Verify OpenShell CLI, Gateway, Docker images, wrappers, policies, and session registry">
          ${panelState.runningDoctor ? 'Checking...' : 'Re-check All'}
        </button>
      </div>
    </div>
  `

  // 1. Sandbox Container Images (4 required images)
  const imagesHtml = imgReport
    ? (() => {
        const rows = (imgReport.images || [])
          .map(img => {
            const dot = img.present ? 'rw' : 'deny'
            const badgeClass = img.present ? 'allow' : 'deny'
            const statusText = img.present ? 'READY' : 'MISSING'
            const sizeHtml = img.size
              ? `<span class="source-pill" style="font-size:10px;">${escapeHtml(img.size)}</span>`
              : ''
            const tooltip = `${img.name}\n${img.role}\nStatus: ${statusText}${img.size ? ` (${img.size})` : ''}${img.createdAt ? `\nCreated: ${img.createdAt}` : ''}`
            return `
            <div class="cmd-row" data-tooltip="${escapeHtml(tooltip)}">
              <div style="display:flex;align-items:center;gap:8px;min-width:0;flex:1;">
                <span class="access-dot ${dot}" title="${img.present ? 'Installed' : 'Missing'}"></span>
                <div style="display:flex;flex-direction:column;gap:1px;min-width:0;">
                  <span class="cmd-code" style="font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${escapeHtml(img.name)}</span>
                  <span class="sub" style="font-size:10.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escapeHtml(img.role)}</span>
                </div>
              </div>
              <div style="display:flex;align-items:center;gap:6px;flex-shrink:0;">
                ${sizeHtml}
                <span class="badge ${badgeClass}">${statusText}</span>
              </div>
            </div>
          `
          })
          .join('')

        const missingAlert = !imgReport.dockerAvailable
          ? `<div class="cmd-row" style="background:var(--danger-bg);border-color:rgba(248,81,73,0.35);flex-direction:column;align-items:flex-start;gap:4px;">
              <div style="display:flex;align-items:center;gap:6px;">
                <span class="access-dot deny"></span>
                <strong style="color:var(--danger);font-size:11.5px;">Docker Daemon Not Reachable</strong>
              </div>
              <span class="sub" style="color:var(--fg);">${escapeHtml(imgReport.error || 'Cannot communicate with Docker. Ensure Docker is running.')}</span>
            </div>`
          : !imgReport.allPresent
            ? `<div class="cmd-row" style="background:var(--danger-bg);border-color:rgba(248,81,73,0.35);justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap;">
                <div style="display:flex;flex-direction:column;gap:2px;min-width:0;flex:1;">
                  <strong style="color:var(--danger);font-size:11.5px;">Missing Required Sandbox Image(s)</strong>
                  <span class="sub">Run <code class="mono">./install.sh</code> in the repository root to build required base and agent images.</span>
                </div>
                <button class="copy-btn primary" data-copy="./install.sh" title="Copy install command to clipboard">Copy ./install.sh</button>
              </div>`
            : ''

        return `${missingAlert}${rows}`
      })()
    : `<div class="sub">No sandbox container image status available.</div>`

  const imagesFoldDot = imagesAllPresent ? 'rw' : 'deny'

  // 2. Prerequisites & Components (CLI, Gateway, Host Wrappers, Base Policies, Native Sync, Delegation)
  const makeStatusRow = (
    label: string,
    detail: string,
    status: 'pass' | 'warn' | 'fail' | 'checking',
    tooltip: string,
    actionHtml = ''
  ) => {
    const dot = status === 'pass' ? 'rw' : status === 'warn' || status === 'checking' ? 'l7' : 'deny'
    const badgeClass =
      status === 'pass' ? 'allow' : status === 'warn' || status === 'checking' ? 'warn' : 'deny'
    const badgeLabel =
      status === 'pass' ? 'READY' : status === 'warn' ? 'WARN' : status === 'checking' ? 'CHECK' : 'MISSING'
    return `
      <div class="cmd-row" data-tooltip="${escapeHtml(tooltip)}">
        <div style="display:flex;align-items:center;gap:8px;min-width:0;flex:1;">
          <span class="access-dot ${dot}"></span>
          <div style="display:flex;flex-direction:column;gap:1px;min-width:0;">
            <span style="font-size:11.5px;font-weight:600;color:var(--fg);">${escapeHtml(label)}</span>
            <span class="sub" style="font-size:10.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escapeHtml(detail)}</span>
          </div>
        </div>
        <div style="display:flex;align-items:center;gap:6px;flex-shrink:0;">
          ${actionHtml}
          <span class="badge ${badgeClass}">${badgeLabel}</span>
        </div>
      </div>
    `
  }

  const cliRowHtml = makeStatusRow(
    'OpenShell CLI',
    cliCheck
      ? cliCheck.detail
      : setup?.openshellInstalled
        ? `Installed at ${setup.openshellBinary}`
        : 'openshell binary not found in PATH',
    cliCheck ? cliCheck.status : setup?.openshellInstalled ? 'pass' : 'fail',
    `OpenShell binary: ${setup?.openshellBinary || 'openshell'}\nRequired for sandbox creation, SSH exec, and L7 policy updates.`
  )

  const gatewayStatus: 'pass' | 'warn' | 'fail' | 'checking' = gatewayCheck
    ? gatewayCheck.status
    : panelState.runningDoctor
      ? 'checking'
      : 'warn'
  const gatewayDetail = gatewayCheck
    ? gatewayCheck.detail
    : panelState.runningDoctor
      ? 'Checking active OpenShell gateway...'
      : 'Click Re-check All to test live gateway reachability.'
  const gatewayRowHtml = makeStatusRow(
    'OpenShell Gateway',
    gatewayDetail,
    gatewayStatus,
    'Verifies connectivity to your active local Docker or remote K3s OpenShell gateway (openshell sandbox list).'
  )

  const missingWrappers = wrappers.filter(w => !w.present).map(w => w.name)
  const wrappersRowHtml = makeStatusRow(
    `Host Bridge Wrappers (${wrappersPresentCount}/${wrappers.length})`,
    wrappersAllPresent
      ? `Installed in ${setup.binDir}`
      : `Missing in ${setup.binDir}: ${missingWrappers.join(', ')}`,
    wrappersAllPresent ? 'pass' : 'fail',
    wrappers.map(w => `${w.present ? '✓' : '✗'} ${w.path}`).join('\n'),
    wrappersAllPresent
      ? ''
      : `<button class="copy-btn" data-copy="./scripts/install-orca-host.sh" title="Copy host bridge installer command">Copy Install</button>`
  )

  const missingPolicies = policies.filter(p => !p.present).map(p => p.name)
  const policiesRowHtml = makeStatusRow(
    `Agent L7 Base Policies (${policiesPresentCount}/${policies.length})`,
    policiesAllPresent
      ? `Installed in ${setup.policyDir}`
      : `Missing in ${setup.policyDir}: ${missingPolicies.join(', ')}`,
    policiesAllPresent ? 'pass' : 'fail',
    policies.map(p => `${p.present ? '✓' : '✗'} ${p.path}`).join('\n'),
    policiesAllPresent
      ? ''
      : `<button class="copy-btn" data-copy="./scripts/install-orca-host.sh" title="Copy host bridge installer command">Copy Install</button>`
  )

  const sync = report.nativeSync
  const syncCount = [sync?.claudeSynced, sync?.codexSynced, sync?.geminiSynced].filter(Boolean).length
  const syncRowHtml = makeStatusRow(
    `Native CLI Permission Sync (${syncCount}/3)`,
    `Claude (${sync?.claudeAllowCount || 0}/${sync?.claudeDenyCount || 0}), Codex (${sync?.codexRuleCount || 0}), Gemini (${sync?.geminiAllowCount || 0}/${sync?.geminiDenyCount || 0})`,
    syncCount === 3 ? 'pass' : syncCount > 0 ? 'warn' : 'warn',
    [
      `Claude: ${sync?.claudeSettingsPath || '~/.claude/settings.json'} (${sync?.claudeSynced ? 'synced' : 'not found'})`,
      `Codex: ${sync?.codexRulesPath || '~/.codex/rules/default.rules'} (${sync?.codexSynced ? 'synced' : 'not found'})`,
      `Gemini: ${sync?.geminiSettingsPath || '~/.gemini/policies/managed-permissions.toml'} (${sync?.geminiSynced ? 'synced' : 'not found'})`,
    ].join('\n')
  )

  const del = report.delegation
  const delegationRowHtml = makeStatusRow(
    'Subagent Delegation Broker',
    del?.autoGrantEnabled
      ? `Auto-Grant ON (${del.allowedAgents.join(', ')} • max ${del.maxWorkers} workers, depth ${del.maxDepth})`
      : `Manual Grant (${del?.activeGrants?.length || 0} active grant${(del?.activeGrants?.length || 0) === 1 ? '' : 's'})`,
    'pass',
    [
      `Auto-Grant: ${del?.autoGrantEnabled ? 'Enabled' : 'Disabled'}`,
      `Config: ${del?.configPath || 'ORCA_AUTO_GRANT_DELEGATION / default'}`,
      `Allowed agents: ${(del?.allowedAgents || []).join(', ')}`,
      `Limits: maxWorkers=${del?.maxWorkers ?? 2}, maxDepth=${del?.maxDepth ?? 1}`,
      `Active grants: ${del?.activeGrants?.length || 0}`,
    ].join('\n')
  )

  const registryRowHtml = registryCheck
    ? makeStatusRow(
        'Session Registry',
        registryCheck.detail,
        registryCheck.status,
        'Tracks active sandbox sessions per tab and prunes stale entries.'
      )
    : ''

  const prereqAllOk = cliOk && gatewayOk !== false && wrappersAllPresent && policiesAllPresent

  return `
    ${summaryBannerHtml}

    <details class="app-fold" data-section="setup-images" ${isSectionOpen('setup-images', true) ? 'open' : ''}>
      <summary>
        <div style="display:flex;align-items:center;gap:8px;">
          <span class="fold-chevron">&#9654;</span>
          <span class="access-dot ${imagesFoldDot}"></span>
          <span>Sandbox Container Images (${imagesPresentCount}/${imagesTotalCount})</span>
        </div>
        <span class="source-pill">&#8984; docker</span>
      </summary>
      <div class="app-fold-body">
        ${imagesHtml}
      </div>
    </details>

    <details class="app-fold" data-section="setup-prereqs" ${isSectionOpen('setup-prereqs', true) ? 'open' : ''}>
      <summary>
        <div style="display:flex;align-items:center;gap:8px;">
          <span class="fold-chevron">&#9654;</span>
          <span class="access-dot ${prereqAllOk ? 'rw' : 'deny'}"></span>
          <span>Prerequisites &amp; Integration</span>
        </div>
        <span class="source-pill">&#8984; host-check</span>
      </summary>
      <div class="app-fold-body">
        ${cliRowHtml}
        ${gatewayRowHtml}
        ${wrappersRowHtml}
        ${policiesRowHtml}
        ${syncRowHtml}
        ${delegationRowHtml}
        ${registryRowHtml}
      </div>
    </details>
  `
}
