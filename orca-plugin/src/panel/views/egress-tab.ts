import { panelState } from '../state.ts'
import { escapeHtml } from '../utils.ts'

export function renderEgressTab(): string {
  const report = panelState.currentReport
  if (!report) return ''

  const a = report.agents[0]
  if (!a) {
    return `<div class="card"><div class="sub">No agent profile found.</div></div>`
  }

  const l7ComposerFoldHtml = `
    <details class="app-fold" data-section="l7-composer" ${panelState.openSections.has('l7-composer') ? 'open' : ''}>
      <summary>
        <div style="display:flex;align-items:center;gap:8px;">
          <span class="fold-chevron">&#9654;</span>
          <span class="access-dot l7"></span>
          <span>+ Add L7 Egress Rule</span>
        </div>
        <span class="source-pill">&#8984; l7-policy</span>
      </summary>
      <div class="app-fold-body">
        <div class="controls">
          <select id="l7Scope" style="max-width:190px;">
            <option value="workspace">Allow (Project Rules)</option>
            <option value="session">Allow Temporarily (Session)</option>
            <option value="global">Allow Global (${escapeHtml(report.currentAgent)}.json)</option>
          </select>
          <select id="l7Action" style="max-width:90px;">
            <option value="allow">ALLOW</option>
            <option value="deny">DENY</option>
          </select>
          <select id="l7Method" style="max-width:90px;">
            <option value="GET">GET</option>
            <option value="POST">POST</option>
            <option value="PUT">PUT</option>
            <option value="PATCH">PATCH</option>
            <option value="DELETE">DELETE</option>
            <option value="*">* (ANY)</option>
          </select>
        </div>
        <div class="controls">
          <input id="l7Host" type="text" class="mono" placeholder="Host (e.g. api.github.com)" style="flex:2;" />
          <input id="l7Port" type="text" class="mono" value="443" placeholder="Port" style="max-width:60px;" />
          <input id="l7Path" type="text" class="mono" value="/repos/**" placeholder="Path (e.g. /repos/**)" style="flex:2;" />
        </div>
        <div class="controls">
          <input id="l7Binary" type="text" class="mono" value="*" placeholder="Binary (e.g. /usr/bin/gh)" style="flex:1;" />
          <input id="l7TriggerCmd" type="text" class="mono" placeholder="Triggering CLI / script" style="flex:2;" />
          <button id="addL7Btn" class="primary">Add</button>
        </div>
        <div id="l7ComposerStatus" style="display:none;" class="eval-result"></div>
      </div>
    </details>
  `

  const filteredEndpoints = a.endpoints.filter(ep => {
    if (!panelState.egressSearch) return true
    const q = panelState.egressSearch.toLowerCase()
    return (
      ep.host.toLowerCase().includes(q) ||
      (ep.ruleScope || '').toLowerCase().includes(q) ||
      (ep.triggerSource || '').toLowerCase().includes(q) ||
      (ep.triggerExplanation || '').toLowerCase().includes(q) ||
      (ep.policyName || '').toLowerCase().includes(q) ||
      (ep.compatibleCliCommands || []).some(c => c.toLowerCase().includes(q))
    )
  })

  const endpointsHtml = filteredEndpoints
    .map(ep => {
      const epKey = `${ep.host}:${ep.port}:${ep.policyName}`
      const isOpen = Boolean(panelState.egressSearch) || panelState.openEgress.has(epKey)
      const isTemporary = Boolean(ep.temporary || ep.ruleScope === 'temporary')
      const isProject = ep.ruleScope === 'project'
      const hasDenyRule =
        (ep.l7Rules || []).some(r => r.action === 'deny') &&
        !(ep.l7Rules || []).some(r => r.action === 'allow')
      const dotClass = hasDenyRule
        ? 'deny'
        : isTemporary
          ? 'l7'
          : ep.access === 'read-only'
            ? 'ro'
            : ep.access === 'l7-rules' || (ep.l7Rules && ep.l7Rules.length > 0)
              ? 'l7'
              : 'rw'
      const triggerLabel =
        ep.triggerSource || (ep.compatibleCliCommands && ep.compatibleCliCommands[0]) || 'cli'
      const scopeBadgeHtml = isTemporary
        ? `<span class="badge warn" title="Allowed temporarily for this session only">Temporary</span>`
        : isProject
          ? `<span class="badge allow" title="Saved in project rules (.agents/policies)">Project</span>`
          : ''
      const explanationText =
        ep.triggerExplanation ||
        `Outbound network egress to ${ep.host}:${ep.port} triggered by ${(ep.compatibleCliCommands || []).join(', ')} (defined in ${ep.source}).`
      const l7Html =
        (ep.l7Rules || []).length > 0
          ? `<div class="chips" style="margin-top:2px;">${ep.l7Rules!
              .map(
                r =>
                  `<span class="right-pill"><span class="access-dot ${r.action === 'deny' ? 'deny' : 'rw'}" style="width:6px;height:6px;box-shadow:none;"></span>${escapeHtml(r.action.toUpperCase())} ${escapeHtml(r.method)} ${escapeHtml(r.path)}</span>`
              )
              .join('')}</div>`
          : ''
      const cliChipsHtml =
        (ep.compatibleCliCommands || []).length > 0
          ? `<div class="chips">${ep.compatibleCliCommands
              .map(
                cmd =>
                  `<button class="copy-btn sample-cmd" data-cmd="${escapeHtml(cmd.replace(/<[^>]+>/g, 'test'))}">${escapeHtml(cmd)}</button>`
              )
              .join('')}</div>`
          : ''
      const firstL7 = (ep.l7Rules && ep.l7Rules[0]) || {
        action: 'allow' as const,
        method: 'GET',
        path: '/**',
      }
      const tempActionsHtml = isTemporary
        ? `<div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:2px;">
            <button
              class="copy-btn primary promote-temp-btn"
              data-host="${escapeHtml(ep.host)}"
              data-port="${escapeHtml(ep.port || 443)}"
              data-action="${escapeHtml(firstL7.action || 'allow')}"
              data-method="${escapeHtml(firstL7.method || 'GET')}"
              data-path="${escapeHtml(firstL7.path || '/**')}"
              title="Promote temporary rule to project rules (.agents/policies/l7-custom.json)"
            >Allow (Add to Project)</button>
            <button
              class="copy-btn remove-temp-btn"
              data-host="${escapeHtml(ep.host)}"
              data-port="${escapeHtml(ep.port || 443)}"
              title="Remove temporary rule tag from session"
            >Remove</button>
          </div>`
        : ''

      return `
        <details class="egress-fold" data-egress="${escapeHtml(epKey)}" ${isOpen ? 'open' : ''}>
          <summary>
            <div style="display:flex;align-items:center;gap:8px;min-width:0;flex:1;">
              <span class="fold-chevron">&#9654;</span>
              <span class="access-dot ${dotClass}" title="Right: ${escapeHtml(ep.access)}"></span>
              <span class="cmd-code" style="font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${escapeHtml(ep.host)}${ep.port && ep.port !== 443 ? ':' + escapeHtml(ep.port) : ''}</span>
              ${scopeBadgeHtml}
            </div>
            <div style="display:flex;align-items:center;gap:6px;flex-shrink:0;">
              <span class="source-pill">&#8984; ${escapeHtml(triggerLabel)}</span>
            </div>
          </summary>
          <div class="egress-fold-body">
            <div style="color:var(--fg);line-height:1.45;">
              ${escapeHtml(explanationText)}
            </div>
            ${l7Html}
            ${tempActionsHtml}
            <div style="display:flex;align-items:center;justify-content:space-between;gap:6px;flex-wrap:wrap;margin-top:2px;">
              ${cliChipsHtml}
              <span class="sub mono">${escapeHtml(ep.sourcePath || ep.source)}</span>
            </div>
          </div>
        </details>
      `
    })
    .join('')

  return `
    ${l7ComposerFoldHtml}
    <div class="controls">
      <input id="egressSearch" type="text" placeholder="Filter host, CLI command, or script (e.g. github, npm, claude)..." value="${escapeHtml(panelState.egressSearch)}" />
      <button id="expandEgressBtn" class="copy-btn">Expand</button>
      <button id="collapseEgressBtn" class="copy-btn">Collapse</button>
    </div>
    <div style="display:flex;flex-direction:column;gap:6px;">
      ${endpointsHtml || '<div class="sub">No matching egress policies found.</div>'}
    </div>
  `
}
