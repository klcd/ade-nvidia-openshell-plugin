import { execFileSync } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import {
  normalizeAgentId,
  type AddL7PolicyRequest,
  type AddL7PolicyResult,
} from '../types.ts'
import { discoverCurrentOrcaContext, resolveCurrentTabSandbox } from '../context/orca-context.ts'
import {
  getAugmentedEnv,
  listActiveSandboxes,
  resolveOpenShellBinary,
} from '../sandbox/sandbox-control.ts'
import { readJsonSafe, withStateLock, writeJsonAtomic } from '../state/file-lock.ts'
import { recordSessionEgressRule, removeSessionEgressRule } from '../state/session-egress.ts'

export const DEFAULT_L7_WILDCARD_BINARIES = [
  '/usr/bin/curl',
  '/usr/bin/git',
  '/usr/local/bin/node',
  '/usr/bin/python3',
  '/usr/bin/gh',
]

export function persistL7PolicyToJsonFile(params: {
  targetFile: string
  ruleName: string
  host: string
  port: number
  action: 'allow' | 'deny'
  method: string
  urlPath: string
  effectiveBinaries: string[]
  triggerCommand?: string
}): void {
  const { targetFile, ruleName, host, port, action, method, urlPath, effectiveBinaries, triggerCommand } = params
  withStateLock(targetFile, () => {
    const doc = readJsonSafe<Record<string, any>>(targetFile, {
      version: 1,
      network_policies: {},
    })
    doc.version ??= 1
    doc.network_policies ??= {}

    const existingPol = doc.network_policies[ruleName] || {
      name: ruleName,
      binaries: effectiveBinaries.map(p => ({ path: p })),
      endpoints: [],
    }
    const bins: Array<{ path: string }> = Array.isArray(existingPol.binaries) ? existingPol.binaries : []
    for (const b of effectiveBinaries) {
      if (!bins.some(item => item?.path === b)) {
        bins.push({ path: b })
      }
    }
    existingPol.binaries = bins

    const endpoints: any[] = Array.isArray(existingPol.endpoints) ? existingPol.endpoints : []
    let ep = endpoints.find(e => e?.host === host && Number(e?.port || 443) === port)
    if (!ep) {
      ep = {
        host,
        port,
        protocol: 'rest',
        enforcement: 'enforce',
      }
      endpoints.push(ep)
    }
    if (triggerCommand && triggerCommand.trim()) {
      ep.trigger_command = triggerCommand.trim()
    }
    // OpenShell L7 rules cannot be combined with access presets on the same endpoint
    delete ep.access

    if (action === 'allow') {
      ep.rules = Array.isArray(ep.rules) ? ep.rules : []
      const exists = ep.rules.some(
        (r: any) => r?.allow?.method === method && r?.allow?.path === urlPath
      )
      if (!exists) {
        ep.rules.push({ allow: { method, path: urlPath } })
      }
    } else {
      ep.deny_rules = Array.isArray(ep.deny_rules) ? ep.deny_rules : []
      const exists = ep.deny_rules.some(
        (d: any) => d?.method === method && d?.path === urlPath
      )
      if (!exists) {
        ep.deny_rules.push({ method, path: urlPath })
      }
    }

    existingPol.endpoints = endpoints
    doc.network_policies[ruleName] = existingPol
    writeJsonAtomic(targetFile, doc)
  })
}

/**
 * Dynamically adds an OpenShell L7 HTTP policy rule either:
 * - 'session': live on the running sandbox(es) via `openshell policy update`
 * - 'workspace': persisted to `<workspace>/.agents/policies/l7-custom.json` (and live-applied if a sandbox is running)
 * - 'global': persisted to `~/.agents/orca-openshell-policies/<agent>.json` (and live-applied if a sandbox is running)
 */
export function addL7Policy(
  req: AddL7PolicyRequest,
  options?: { homeDir?: string; orcaPolicyDir?: string }
): AddL7PolicyResult {
  const homeDir = options?.homeDir || os.homedir()
  const orcaPolicyDir =
    options?.orcaPolicyDir ||
    process.env.ORCA_OPENSHELL_POLICY_DIR ||
    path.join(homeDir, '.agents', 'orca-openshell-policies')

  const host = String(req.host || '').trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '')
  if (!host || !/^[a-zA-Z0-9.-]+$/.test(host)) {
    return {
      ok: false,
      scope: req.scope,
      message: `Invalid hostname '${req.host}'. Provide a valid domain (e.g. api.github.com).`,
    }
  }

  const port = Number(req.port || 443)
  const action: 'allow' | 'deny' = req.action === 'deny' ? 'deny' : 'allow'
  const method = String(req.method || 'GET').trim().toUpperCase() || 'GET'
  const rawPath = String(req.path || '/**').trim()
  const urlPath = rawPath.startsWith('/') ? rawPath : `/${rawPath}`
  const binary = String(req.binary || '*').trim() || '*'
  const effectiveBinaries = binary === '*' ? DEFAULT_L7_WILDCARD_BINARIES : [binary]
  const ruleName =
    String(req.ruleName || `${host.replace(/[^a-zA-Z0-9]+/g, '_')}_l7`)
      .trim()
      .replace(/[^a-zA-Z0-9_-]/g, '_') || 'custom_l7'

  const cliCommandsRun: string[] = []
  const appliedSandboxes: string[] = []
  let targetFile: string | undefined
  const wsPath = req.workspacePath || discoverCurrentOrcaContext({ homeDir }).workspace.path
  const resolvedAgent = normalizeAgentId(req.agent) || discoverCurrentOrcaContext({ homeDir }).currentAgent

  // 1. Persist to JSON policy file when scope is 'workspace' or 'global'
  if (req.scope === 'workspace' || req.scope === 'global') {
    targetFile =
      req.scope === 'workspace'
        ? path.join(wsPath, '.agents', 'policies', 'l7-custom.json')
        : path.join(orcaPolicyDir, `${resolvedAgent}.json`)

    persistL7PolicyToJsonFile({
      targetFile,
      ruleName,
      host,
      port,
      action,
      method,
      urlPath,
      effectiveBinaries,
      triggerCommand: req.triggerCommand,
    })

    // Promote: remove any temporary session rule for this endpoint/path now that it is saved permanently
    removeSessionEgressRule({ workspacePath: wsPath, host, port }, homeDir)
  }

  // 2. Apply dynamically to running sandbox(es) via `openshell policy update`
  const targetSandboxes: string[] = []
  let resolvedTabSandboxName: string | undefined = req.sandboxName || undefined
  if (req.sandboxName) {
    targetSandboxes.push(req.sandboxName)
  } else if (req.scope === 'global') {
    for (const sb of listActiveSandboxes()) {
      if (sb.agent === resolvedAgent && sb.phase.toLowerCase() === 'ready') {
        targetSandboxes.push(sb.name)
      }
    }
  } else {
    const ctx = discoverCurrentOrcaContext({ workspacePath: wsPath, agent: resolvedAgent, homeDir })
    const tabSandboxes = resolveCurrentTabSandbox({
      allSandboxes: listActiveSandboxes(),
      selectedWorkspace: ctx.workspace,
      currentAgent: resolvedAgent,
      activeAgentSessions: ctx.activeAgentSessions,
      homeDir,
    })
    if (tabSandboxes[0]?.name) {
      resolvedTabSandboxName = tabSandboxes[0].name
    }
    for (const sb of tabSandboxes) {
      if (sb.phase.toLowerCase() === 'ready') {
        targetSandboxes.push(sb.name)
      }
    }
  }

  const binFlags = effectiveBinaries.flatMap(b => ['--binary', b])
  const liveErrors: string[] = []
  const openshellBin = resolveOpenShellBinary(homeDir)
  const env = getAugmentedEnv(homeDir)
  for (const sbName of targetSandboxes) {
    const step1Args = [
      'policy',
      'update',
      sbName,
      '--rule-name',
      ruleName,
      ...binFlags,
      '--add-endpoint',
      `${host}:${port}:read-write:rest:enforce`,
    ]
    const step2Args = [
      'policy',
      'update',
      sbName,
      '--rule-name',
      ruleName,
      ...binFlags,
      action === 'allow' ? '--add-allow' : '--add-deny',
      `${host}:${port}:${method}:${urlPath}`,
    ]
    cliCommandsRun.push(`openshell ${step1Args.join(' ')}`)
    cliCommandsRun.push(`openshell ${step2Args.join(' ')}`)

    try {
      execFileSync(openshellBin, step1Args, {
        encoding: 'utf8',
        timeout: 8000,
        stdio: ['ignore', 'pipe', 'pipe'],
        env,
      })
      execFileSync(openshellBin, step2Args, {
        encoding: 'utf8',
        timeout: 8000,
        stdio: ['ignore', 'pipe', 'pipe'],
        env,
      })
      appliedSandboxes.push(sbName)
    } catch (err: any) {
      liveErrors.push(`${sbName}: ${err?.stderr?.toString()?.trim() || err?.message || String(err)}`)
    }
  }

  if (req.scope === 'session' && targetSandboxes.length > 0 && appliedSandboxes.length === 0 && liveErrors.length > 0) {
    return {
      ok: false,
      scope: 'session',
      message: `Failed to apply live L7 policy: ${liveErrors.join('; ')}`,
      cliCommandsRun,
    }
  }

  if (req.scope === 'session') {
    recordSessionEgressRule(
      {
        sandboxName: appliedSandboxes[0] || resolvedTabSandboxName || undefined,
        workspacePath: wsPath,
        agent: resolvedAgent,
        ruleName,
        host,
        port,
        action,
        method,
        path: urlPath,
        binary,
        ...(req.triggerCommand?.trim() ? { triggerCommand: req.triggerCommand.trim() } : {}),
        createdAt: new Date().toISOString(),
      },
      homeDir
    )
  }

  const summaryParts: string[] = []
  if (req.scope === 'session') {
    summaryParts.push(`Added temporary L7 ${action.toUpperCase()} rule (${method} https://${host}:${port}${urlPath})`)
  } else if (targetFile) {
    summaryParts.push(`Saved L7 ${action.toUpperCase()} rule (${method} https://${host}:${port}${urlPath}) to ${targetFile}`)
  }
  if (appliedSandboxes.length > 0) {
    summaryParts.push(`Live-applied to running sandbox(es): ${appliedSandboxes.join(', ')}`)
  } else if (liveErrors.length > 0) {
    summaryParts.push(`Live sandbox note: ${liveErrors.join('; ')}`)
  }

  return {
    ok: true,
    scope: req.scope,
    message: summaryParts.join(' - '),
    ...(targetFile ? { targetFile } : {}),
    appliedSandboxes,
    cliCommandsRun,
  }
}

export function removeTemporaryL7Rule(
  req: { sandboxName?: string; workspacePath?: string; host: string; port?: number },
  options?: { homeDir?: string }
): { ok: boolean } {
  const homeDir = options?.homeDir || os.homedir()
  const wsPath = req.workspacePath || discoverCurrentOrcaContext({ homeDir }).workspace.path
  let targetSandboxName = req.sandboxName
  if (targetSandboxName === undefined) {
    const ctx = discoverCurrentOrcaContext({ workspacePath: wsPath, homeDir })
    const tabSb = resolveCurrentTabSandbox({
      allSandboxes: listActiveSandboxes(),
      selectedWorkspace: ctx.workspace,
      currentAgent: ctx.currentAgent,
      activeAgentSessions: ctx.activeAgentSessions,
      homeDir,
    })[0]
    if (tabSb?.name) {
      targetSandboxName = tabSb.name
    }
  }
  const removed = removeSessionEgressRule(
    {
      ...(targetSandboxName !== undefined ? { sandboxName: targetSandboxName } : {}),
      workspacePath: wsPath,
      host: req.host,
      port: req.port,
    },
    homeDir
  )
  return { ok: removed }
}
