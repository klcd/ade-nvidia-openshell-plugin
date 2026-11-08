// Orca invokes this worker for terminal agent launches, the OpenShell Policies panel, and CLI policy inspection commands.
import type { OrcaWorkerApi } from 'orca/worker'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { addL7Policy, type AddL7PolicyRequest, buildPolicyReport, evaluateCommandPolicy } from './policy-inspector.ts'

const wrappers: Record<string, string> = {
  codex: 'codex-box',
  claude: 'claude-box',
  antigravity: 'agy-box',
  agy: 'agy-box',
}

const allowedExecutables: Record<string, string[]> = {
  codex: ['codex'],
  claude: ['claude'],
  antigravity: ['antigravity', 'agy'],
  agy: ['antigravity', 'agy'],
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`
}

/** Preserve Orca's arguments and prompt while replacing the first command token. */
export function bridgeCommand(agent: string, command: string, binDir: string): string | null {
  const wrapper = wrappers[agent]
  if (!wrapper) return null
  const executable = path.join(binDir, wrapper)
  if (!fs.existsSync(executable) || !fs.statSync(executable).isFile()) {
    throw new Error(`OpenShell bridge wrapper is missing: ${executable}`)
  }
  const match = /^(\s*)([\w./-]+)(?=\s|$)/.exec(command)
  const allowed = allowedExecutables[agent] || [agent]
  if (!match || !allowed.includes(path.basename(match[2]))) {
    throw new Error(`Unexpected ${agent} launch command; refusing an unverified rewrite`)
  }
  return `${match[1]}${shellQuote(executable)}${command.slice(match[0].length)}`
}

/** Format a concise text summary of allowed policies and coupled CLI commands for the command palette. */
export function formatCliPolicySummary(workspacePath?: string): string {
  const report = buildPolicyReport({ workspacePath })
  const lines: string[] = [
    `=== OpenShell Policy & CLI Command Report (${report.selectedWorkspace.name}) ===`,
    `Active Sandboxes: ${report.activeSandboxes.length > 0 ? report.activeSandboxes.map(s => `${s.name} (${s.phase})`).join(', ') : 'none'}`,
    '',
    '1. Agent Launch Policies & Coupled CLI Commands:',
  ]

  for (const agent of report.agents) {
    lines.push(`  • ${agent.displayName} (${agent.agent}) — Landlock: ${agent.landlockMode}, Profile: ${agent.providerProfile}`)
    for (const s of agent.surfaces) {
      lines.push(`      [${s.surface}] ${s.cliExample}`)
    }
    lines.push(`      Allowed Binaries: ${agent.allowedBinaries.join(', ')}`)
    lines.push(`      Allowed Egress:   ${agent.endpoints.map(e => `${e.host}:${e.port} (${e.access})`).join(', ')}`)
  }

  lines.push('', '2. Canonical CLI Command Permission Groups (DENY > ASK > ALLOW):')
  for (const group of report.permissionGroups) {
    const allows = group.rules.filter(r => r.action === 'allow').map(r => r.cliCommand)
    const denies = group.rules.filter(r => r.action === 'deny').map(r => r.cliCommand)
    lines.push(`  • [${group.scope}] ${group.name} (${group.sourceFile}) — ${group.description}`)
    if (allows.length > 0) lines.push(`      ALLOW (${allows.length}): ${allows.join(' | ')}`)
    if (denies.length > 0) lines.push(`      DENY  (${denies.length}): ${denies.join(' | ')}`)
  }

  lines.push('', '3. In-Sandbox Orchestration Delegation CLI Commands:')
  for (const cmd of report.delegation.allowedCliCommands) {
    lines.push(`  • ${cmd.command}`)
  }

  return lines.join('\n')
}

export default function activate(orca: OrcaWorkerApi): void {
  let lastAgent: string | undefined

  const refreshStatusBar = () => {
    if (!orca.host?.call) return
    try {
      const report = buildPolicyReport({ agent: lastAgent })
      const activeCount = report.activeSandboxes.length
      const allowCount = report.allCliRules.filter(r => r.action === 'allow').length
      const text = activeCount > 0
        ? `OpenShell (${report.currentAgent}): ${activeCount} sandbox${activeCount === 1 ? '' : 'es'} (${allowCount} CLI rules)`
        : `OpenShell (${report.currentAgent}): Enforced (${allowCount} CLI rules)`
      void orca.host.call('statusBar.update', {
        id: 'openshell-status',
        text,
        icon: 'layers',
        tone: activeCount > 0 ? 'accent' : 'success',
        tooltip: `Project: ${report.selectedWorkspace.name} • Agent: ${report.currentAgent} • ${activeCount} active sandbox(es) • ${allowCount} allowed CLI command patterns`,
        visible: true,
      }).catch(() => {})
    } catch {}
  }

  orca.hooks.on('agent.launch.before', (event, next) => {
    if (event.agent) lastAgent = event.agent
    if (!(event.agent in wrappers)) return next()
    try {
      const binDir = process.env.ORCA_OPENSHELL_BRIDGE_BIN_DIR || path.join(os.homedir(), '.local', 'bin')
      const command = bridgeCommand(event.agent, event.command, binDir)
      if (!command) return { deny: 'No OpenShell bridge wrapper is configured for this agent' }
      const policyDir = process.env.ORCA_OPENSHELL_POLICY_DIR || path.join(os.homedir(), '.agents', 'orca-openshell-policies')
      let policyFile = path.join(policyDir, `${event.agent}.json`)
      if (!fs.existsSync(policyFile)) {
        if (event.agent === 'antigravity') policyFile = path.join(policyDir, 'agy.json')
        else if (event.agent === 'agy') policyFile = path.join(policyDir, 'antigravity.json')
      }
      if (!fs.existsSync(policyFile)) return { deny: `OpenShell policy is missing: ${policyFile}` }
      const safeEnv = Object.fromEntries(Object.entries(event.env).filter(([key]) => !key.startsWith('OPENSHELL_BRIDGE_')))
      orca.log(`OpenShell bridge selected for ${event.agent} in ${event.workspaceId ?? 'unknown workspace'}`)
      setTimeout(refreshStatusBar, 1500)
      return next({ ...event, command, env: {
        ...safeEnv,
        OPENSHELL_BRIDGE_REQUIRED: '1',
        OPENSHELL_BRIDGE_POLICY_FILE: policyFile,
        ...(event.terminalId && event.workspaceId ? {
          OPENSHELL_BRIDGE_TERMINAL_ID: event.terminalId,
          OPENSHELL_BRIDGE_WORKSPACE_ID: event.workspaceId,
        } : {}),
      } })
    } catch (error) {
      return { deny: String(error) }
    }
  })

  orca.panels?.handle('getPolicyReport', (input) => {
    const req = (input && typeof input === 'object' ? input : {}) as { workspacePath?: string; agent?: string }
    const report = buildPolicyReport({
      workspacePath: req.workspacePath,
      agent: req.agent || lastAgent,
    })
    refreshStatusBar()
    return report
  })

  orca.panels?.handle('evaluateCommand', (input) => {
    const req = (input && typeof input === 'object' ? input : {}) as { command?: string; workspacePath?: string; agent?: string }
    const report = buildPolicyReport({
      workspacePath: req.workspacePath,
      agent: req.agent || lastAgent,
    })
    return evaluateCommandPolicy(String(req.command || ''), report)
  })

  orca.panels?.handle('addL7Policy', (input) => {
    const req = (input && typeof input === 'object' ? input : {}) as unknown as Partial<AddL7PolicyRequest>
    const res = addL7Policy({
      scope: req.scope || 'workspace',
      host: req.host || '',
      ...req,
      agent: req.agent || lastAgent,
    })
    refreshStatusBar()
    return res
  })

  orca.commands?.register('openshell.inspectPolicies', () => {
    refreshStatusBar()
    return formatCliPolicySummary()
  })

  refreshStatusBar()
  const timer = setInterval(refreshStatusBar, 3000)
  timer.unref?.()
}
