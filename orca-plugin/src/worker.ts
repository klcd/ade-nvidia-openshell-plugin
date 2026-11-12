// Orca invokes this worker for terminal agent launches, the OpenShell Policies panel, and CLI policy inspection commands.
import type { OrcaWorkerApi } from 'orca/worker'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import {
  addL7Policy,
  type AddL7PolicyRequest,
  buildPolicyReport,
  buildPolicyReportAsync,
  detectRuntimeL7Block,
  discoverCurrentOrcaContext,
  evaluateCommandPolicy,
  executeTestCliCommand,
  getSandboxMode,
  listActiveSandboxes,
  pauseActiveSandbox,
  type PolicyInspectionReport,
  refreshOrcaContextCache,
  removeTemporaryL7Rule,
  resolveCurrentTabSandbox,
  resolveWorkspacePathById,
  resumeActiveSandbox,
  runSandboxDoctor,
  setDefaultSandboxEnabled,
  setSandboxIdleTimeoutSeconds,
  setSandboxMode,
  stopActiveSandbox,
} from './policy-inspector.ts'

const wrappers: Record<string, string> = {
  codex: 'codex-box',
  claude: 'claude-box',
  antigravity: 'agy-box',
  agy: 'agy-box',
}

const allowedExecutables: Record<string, string[]> = {
  codex: ['codex', 'codex-box'],
  claude: ['claude', 'claude-box'],
  antigravity: ['antigravity', 'agy', 'agy-box'],
  agy: ['antigravity', 'agy', 'agy-box'],
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
    `Sandbox Mode: ${report.sandboxEnabled ? 'Enforced' : 'Deactivated (Host Mode)'}`,
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

  const updateStatusBarFromReport = (report: PolicyInspectionReport) => {
    if (!orca.host?.call) return
    try {
      const currentSb = report.activeSandboxes[0] || null
      const isPaused = Boolean(currentSb && /stopped/i.test(currentSb.phase || ''))
      const isRunning = Boolean(currentSb && !isPaused)
      const egressCount = report.agents[0]?.endpoints?.length || 0
      const enabled = report.sandboxEnabled !== false
      const text = !enabled ? 'Hostmode' : 'Sandbox'
      const tone = !enabled ? 'warning' : isRunning ? 'accent' : 'success'
      const tooltip = !enabled
        ? `Hostmode (${report.selectedWorkspace.name}) — Running directly on the host. Click to work inside an OpenShell sandbox.`
        : currentSb
          ? `Working inside OpenShell sandbox ${currentSb.name} (${report.currentAgent}, ${isPaused ? 'Paused' : currentSb.phase}, ${egressCount} egress hosts) — Project: ${report.selectedWorkspace.name}. Click to work directly on the host (Hostmode).`
          : `Working inside an OpenShell sandbox (${report.currentAgent}, ${egressCount} egress hosts) — Project: ${report.selectedWorkspace.name}. Click to work directly on the host (Hostmode).`
      void orca.host.call('statusBar.update', {
        id: 'openshell-status',
        text,
        icon: 'layers',
        tone,
        tooltip,
        visible: true,
      }).catch(() => {})
    } catch {}
  }

  const broadcastReportToPanels = (report: PolicyInspectionReport) => {
    try {
      orca.panels?.post?.('reportUpdated', JSON.parse(JSON.stringify(report)))
    } catch {}
  }

  const refreshStatusBar = () => {
    if (!orca.host?.call) return
    void buildPolicyReportAsync({ fallbackAgent: lastAgent })
      .then(updateStatusBarFromReport)
      .catch(() => {})
  }

  orca.hooks.on('agent.launch.before', (event, next) => {
    if (event.agent) lastAgent = event.agent
    if (!(event.agent in wrappers)) return next()
    const safeEnv = Object.fromEntries(
      Object.entries(event.env).filter(
        ([key]) => !key.startsWith('OPENSHELL_BRIDGE_') && key !== 'OPENSHELL_SANDBOX_DISABLED'
      )
    )
    const launchWorkspacePath = resolveWorkspacePathById(event.workspaceId)
    if (!getSandboxMode({ workspacePath: launchWorkspacePath, workspaceId: event.workspaceId }).enabled) {
      orca.log(`OpenShell sandboxing deactivated for worktree; launching ${event.agent} on host in ${event.workspaceId ?? launchWorkspacePath ?? 'unknown workspace'}`)
      setTimeout(refreshStatusBar, 500)
      return next({
        ...event,
        env: {
          ...safeEnv,
          OPENSHELL_SANDBOX_DISABLED: '1',
        },
      })
    }
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

  const toStrictJson = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T

  orca.panels?.handle('getPolicyReport', async (input) => {
    const req = (input && typeof input === 'object' ? input : {}) as { workspacePath?: string; agent?: string }
    const report = await buildPolicyReportAsync({
      workspacePath: req.workspacePath,
      agent: req.agent,
      fallbackAgent: lastAgent,
    })
    updateStatusBarFromReport(report)
    return toStrictJson(report)
  })

  orca.panels?.handle('setSandboxMode', async (input) => {
    const req = (input && typeof input === 'object' ? input : {}) as {
      enabled?: boolean
      workspacePath?: string
      workspaceId?: string
      parentPaths?: Record<string, string>
      agent?: string
    }
    const targetWorkspacePath =
      req.workspacePath ||
      resolveWorkspacePathById(req.workspaceId) ||
      discoverCurrentOrcaContext({ agent: req.agent, fallbackAgent: lastAgent }).workspace.path
    setSandboxMode(Boolean(req.enabled), {
      workspacePath: targetWorkspacePath,
      workspaceId: req.workspaceId,
      parentPaths: req.parentPaths,
    })
    const report = await buildPolicyReportAsync({
      workspacePath: req.workspacePath || targetWorkspacePath,
      agent: req.agent,
      fallbackAgent: lastAgent,
    })
    updateStatusBarFromReport(report)
    broadcastReportToPanels(report)
    return toStrictJson(report)
  })

  orca.panels?.handle('setDefaultSandboxMode', async (input) => {
    const req = (input && typeof input === 'object' ? input : {}) as {
      enabled?: boolean
      workspacePath?: string
      agent?: string
    }
    setDefaultSandboxEnabled(Boolean(req.enabled))
    const report = await buildPolicyReportAsync({
      workspacePath: req.workspacePath,
      agent: req.agent,
      fallbackAgent: lastAgent,
    })
    updateStatusBarFromReport(report)
    broadcastReportToPanels(report)
    return toStrictJson(report)
  })

  orca.panels?.handle('setSandboxIdleTimeout', async (input) => {
    const req = (input && typeof input === 'object' ? input : {}) as {
      seconds?: number
      sandboxName?: string
      paneKey?: string
      agentSessionId?: string
      terminalId?: string
      workspacePath?: string
      agent?: string
    }
    const ctx = discoverCurrentOrcaContext({
      workspacePath: req.workspacePath,
      agent: req.agent,
      fallbackAgent: lastAgent,
    })
    const currentTabSb =
      req.sandboxName ||
      resolveCurrentTabSandbox({
        allSandboxes: listActiveSandboxes(),
        selectedWorkspace: ctx.workspace,
        currentAgent: ctx.currentAgent,
        activeAgentSessions: ctx.activeAgentSessions,
      })[0]?.name
    const activePaneKey = req.paneKey || ctx.activeAgentSessions[0]?.paneKey || undefined

    setSandboxIdleTimeoutSeconds(Number(req.seconds ?? 300), {
      sandboxName: currentTabSb,
      paneKey: activePaneKey,
      agentSessionId: req.agentSessionId,
      terminalId: req.terminalId,
      workspacePath: req.workspacePath || ctx.workspace.path,
      agent: req.agent || ctx.currentAgent,
    })
    const report = await buildPolicyReportAsync({
      workspacePath: req.workspacePath,
      agent: req.agent,
      fallbackAgent: lastAgent,
    })
    updateStatusBarFromReport(report)
    return toStrictJson(report)
  })

  orca.panels?.handle('pauseSandbox', async (input) => {
    const req = (input && typeof input === 'object' ? input : {}) as {
      sandboxName?: string
      workspacePath?: string
      agent?: string
    }
    const res = await pauseActiveSandbox(String(req.sandboxName || ''))
    const report = await buildPolicyReportAsync({
      workspacePath: req.workspacePath,
      agent: req.agent,
      fallbackAgent: lastAgent,
    })
    updateStatusBarFromReport(report)
    return toStrictJson({ ...res, report })
  })

  orca.panels?.handle('resumeSandbox', async (input) => {
    const req = (input && typeof input === 'object' ? input : {}) as {
      sandboxName?: string
      workspacePath?: string
      agent?: string
    }
    const res = await resumeActiveSandbox(String(req.sandboxName || ''))
    const report = await buildPolicyReportAsync({
      workspacePath: req.workspacePath,
      agent: req.agent,
      fallbackAgent: lastAgent,
    })
    updateStatusBarFromReport(report)
    return toStrictJson({ ...res, report })
  })

  orca.panels?.handle('stopSandbox', async (input) => {
    const req = (input && typeof input === 'object' ? input : {}) as {
      sandboxName?: string
      workspacePath?: string
      agent?: string
    }
    const res = await stopActiveSandbox(String(req.sandboxName || ''))
    const report = await buildPolicyReportAsync({
      workspacePath: req.workspacePath,
      agent: req.agent,
      fallbackAgent: lastAgent,
    })
    updateStatusBarFromReport(report)
    return toStrictJson({ ...res, report })
  })

  orca.panels?.handle('evaluateCommand', async (input) => {
    const req = (input && typeof input === 'object' ? input : {}) as {
      command?: string
      workspacePath?: string
      agent?: string
      execute?: boolean
      forceExecute?: boolean
    }
    const command = String(req.command || '')
    const report = await buildPolicyReportAsync({
      workspacePath: req.workspacePath,
      agent: req.agent,
      fallbackAgent: lastAgent,
    })
    const evalResult = evaluateCommandPolicy(command, report)
    if (req.execute && command.trim()) {
      if (evalResult.verdict === 'deny' && report.sandboxEnabled === false && !req.forceExecute) {
        evalResult.execution = {
          executed: false,
          target: 'host',
          sandboxName: null,
          cwd: report.selectedWorkspace.path,
          exitCode: null,
          stdout: '',
          stderr: '',
          durationMs: 0,
          skippedReason: 'Blocked by DENY policy in Host Mode.',
        }
      } else {
        const execution = await executeTestCliCommand(command, report)
        evalResult.execution = execution
        const runtimeL7 = detectRuntimeL7Block(command, execution.stdout, execution.stderr)
        if (runtimeL7 && !evalResult.l7Suggestion) {
          evalResult.l7Suggestion = runtimeL7
          evalResult.verdict = 'deny'
          evalResult.summary = `Network egress to ${runtimeL7.host}:${runtimeL7.port} was blocked at runtime by the OpenShell L7 proxy.`
        }
        refreshStatusBar()
      }
    }
    return toStrictJson(evalResult)
  })

  orca.panels?.handle('addL7Policy', (input) => {
    const req = (input && typeof input === 'object' ? input : {}) as unknown as Partial<AddL7PolicyRequest>
    const res = addL7Policy({
      scope: req.scope || 'workspace',
      host: req.host || '',
      ...req,
      agent: req.agent,
    })
    refreshStatusBar()
    return toStrictJson(res)
  })

  orca.panels?.handle('removeTemporaryL7Rule', async (input) => {
    const req = (input && typeof input === 'object' ? input : {}) as {
      sandboxName?: string
      workspacePath?: string
      host?: string
      port?: number
      agent?: string
    }
    const res = removeTemporaryL7Rule({
      sandboxName: req.sandboxName,
      workspacePath: req.workspacePath,
      host: String(req.host || ''),
      port: req.port,
    })
    const report = await buildPolicyReportAsync({
      workspacePath: req.workspacePath,
      agent: req.agent,
      fallbackAgent: lastAgent,
    })
    updateStatusBarFromReport(report)
    return toStrictJson({ ...res, report })
  })

  orca.panels?.handle('runDoctor', async (input) => {
    const req = (input && typeof input === 'object' ? input : {}) as {
      workspacePath?: string
      agent?: string
    }
    const doctor = await runSandboxDoctor()
    const report = await buildPolicyReportAsync({
      workspacePath: req.workspacePath,
      agent: req.agent,
      fallbackAgent: lastAgent,
    })
    updateStatusBarFromReport(report)
    return toStrictJson({ doctor, report })
  })

  orca.commands?.register('openshell.inspectPolicies', async (input) => {
    const req = (input && typeof input === 'object' ? input : {}) as {
      workspacePath?: string
      workspaceId?: string
      agent?: string
      enabled?: boolean
      inspectOnly?: boolean
    }
    if (!req.workspacePath) {
      await refreshOrcaContextCache(undefined, true)
    }
    const ctx = discoverCurrentOrcaContext({
      workspacePath: req.workspacePath,
      agent: req.agent,
      fallbackAgent: lastAgent,
    })
    const targetWorkspacePath =
      req.workspacePath || resolveWorkspacePathById(req.workspaceId) || ctx.workspace.path
    const targetWorkspaceId = req.workspaceId || ctx.workspace.id

    if (req.inspectOnly) {
      const report = await buildPolicyReportAsync({
        workspacePath: targetWorkspacePath,
        agent: req.agent,
        fallbackAgent: lastAgent,
      })
      updateStatusBarFromReport(report)
      return formatCliPolicySummary(targetWorkspacePath)
    }

    const currentMode = getSandboxMode({
      workspacePath: targetWorkspacePath,
      workspaceId: targetWorkspaceId,
    })
    const nextEnabled = typeof req.enabled === 'boolean' ? req.enabled : !currentMode.enabled
    setSandboxMode(nextEnabled, {
      workspacePath: targetWorkspacePath,
      workspaceId: targetWorkspaceId,
    })

    const report = await buildPolicyReportAsync({
      workspacePath: targetWorkspacePath,
      agent: req.agent,
      fallbackAgent: lastAgent,
    })
    updateStatusBarFromReport(report)
    broadcastReportToPanels(report)

    const modeLabel = report.sandboxEnabled ? 'On (Enforced)' : 'Off (Host Mode)'
    orca.log?.(`Toggled OpenShell sandbox mode for ${report.selectedWorkspace.name} (${targetWorkspacePath}) -> ${modeLabel}`)
    return `OpenShell Sandbox for ${report.selectedWorkspace.name}: ${modeLabel}`
  })

  ;(orca as any).events?.on?.('workspace.changed', () => {
    void refreshOrcaContextCache(undefined, true).then(() => {
      refreshStatusBar()
    })
  })

  refreshStatusBar()
  const timer = setInterval(refreshStatusBar, 4000)
  timer.unref?.()
}
