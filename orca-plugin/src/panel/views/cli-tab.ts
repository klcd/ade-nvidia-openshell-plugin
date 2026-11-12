import type { CliPermissionRule } from '../../types.ts'
import { panelState } from '../state.ts'
import { escapeHtml } from '../utils.ts'

export function renderCliTab(): string {
  const report = panelState.currentReport
  if (!report) return ''

  const selectedAgent = report.currentAgent
  const filteredRules = report.allCliRules.filter(r => {
    if (!r.compatibleAgents.includes(selectedAgent)) return false
    if (panelState.actionFilter !== 'all' && r.action !== panelState.actionFilter) return false
    if (!panelState.searchFilter) return true
    const q = panelState.searchFilter.toLowerCase()
    return (
      r.cliCommand.toLowerCase().includes(q) ||
      r.baseBinary.toLowerCase().includes(q) ||
      r.raw.toLowerCase().includes(q) ||
      r.groupName.toLowerCase().includes(q)
    )
  })

  const byApp = new Map<string, CliPermissionRule[]>()
  for (const r of filteredRules) {
    const appKey = r.baseBinary || r.tool || 'other'
    if (!byApp.has(appKey)) byApp.set(appKey, [])
    byApp.get(appKey)!.push(r)
  }

  const sortedApps = [...byApp.entries()].sort((a, b) => a[0].localeCompare(b[0]))

  const appsHtml = sortedApps
    .map(([appName, rules]) => {
      const allowCount = rules.filter(r => r.action === 'allow').length
      const askCount = rules.filter(r => r.action === 'ask').length
      const denyCount = rules.filter(r => r.action === 'deny').length
      const sources = [...new Set(rules.map(r => r.groupName))].join(', ')
      const isOpen = Boolean(panelState.searchFilter) || panelState.openApps.has(appName)
      const appDotClass =
        denyCount > 0 && allowCount === 0
          ? 'deny'
          : askCount > 0 && allowCount === 0
            ? 'l7'
            : 'rw'

      const rows = rules
        .map(r => {
          const dotClass = r.action === 'deny' ? 'deny' : r.action === 'ask' ? 'l7' : 'rw'
          const cleanCmd = r.cliCommand.replace(/\s*\[args\.\.\.\]/, '')
          const scopePath =
            r.scope === 'global'
              ? `~/.agents/permissions/${r.sourceFile}`
              : `.agents/permissions/${r.sourceFile}`
          const tooltipLines = [
            `${r.action.toUpperCase()} • ${r.raw}`,
            `Policy: ${r.groupName} (${scopePath})`,
            ...(r.groupDescription ? [r.groupDescription] : []),
          ]
          const tooltip = tooltipLines.join('\n')

          return `
            <div class="cmd-row" data-tooltip="${escapeHtml(tooltip)}">
              <div style="display:flex;align-items:center;gap:8px;min-width:0;flex:1;">
                <span class="access-dot ${dotClass}"></span>
                <span class="cmd-code" style="font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${escapeHtml(r.cliCommand)}</span>
              </div>
              <div style="display:flex;align-items:center;gap:4px;flex-shrink:0;">
                <span class="source-pill" data-tooltip="${escapeHtml(tooltip)}">&#8984; ${escapeHtml(r.groupName)}</span>
              </div>
            </div>
          `
        })
        .join('')

      return `
        <details class="app-fold" data-app="${escapeHtml(appName)}" ${isOpen ? 'open' : ''}>
          <summary>
            <div style="display:flex;align-items:center;gap:8px;min-width:0;flex:1;">
              <span class="fold-chevron">&#9654;</span>
              <span class="access-dot ${appDotClass}"></span>
              <code class="mono" style="font-size:12px;font-weight:700;">${escapeHtml(appName)}</code>
              <span class="sub" style="font-weight:400;">(${rules.length})</span>
            </div>
            <div style="display:flex;gap:4px;align-items:center;flex-shrink:0;">
              <span class="source-pill">&#8984; ${escapeHtml(sources)}</span>
            </div>
          </summary>
          <div class="app-fold-body">
            ${rows}
          </div>
        </details>
      `
    })
    .join('')

  return `
    <div class="controls">
      <input id="ruleSearch" type="text" placeholder="Filter CLI command (e.g. git, docker, kubectl, orca)..." value="${escapeHtml(panelState.searchFilter)}" />
      <select id="actionSelect" style="max-width:105px;">
        <option value="all" ${panelState.actionFilter === 'all' ? 'selected' : ''}>All</option>
        <option value="allow" ${panelState.actionFilter === 'allow' ? 'selected' : ''}>Allow</option>
        <option value="ask" ${panelState.actionFilter === 'ask' ? 'selected' : ''}>Ask</option>
        <option value="deny" ${panelState.actionFilter === 'deny' ? 'selected' : ''}>Deny</option>
      </select>
      <button id="expandAllBtn" class="copy-btn">Expand</button>
      <button id="collapseAllBtn" class="copy-btn">Collapse</button>
    </div>
    ${appsHtml || '<div class="card"><div class="sub">No matching CLI permission rules found.</div></div>'}
  `
}
