import crypto from 'node:crypto'
import fs from 'node:fs'
import net from 'node:net'
import os from 'node:os'
import path from 'node:path'
import {
  extractAgentSessionIdFromPaneKey,
  normalizeAgentId,
  type ActiveAgentSessionInfo,
  type ActiveSandboxInfo,
  type CurrentOrcaContext,
  type OrcaWorktreePsEntry,
  type WorkspaceEntry,
} from '../types.ts'
import { listActiveSandboxes } from '../sandbox/sandbox-control.ts'
import { syncOrcaWorktreeLineage } from '../state/sandbox-mode.ts'
import { readSandboxRegistryMap } from '../state/sandbox-registry.ts'
import {
  getCachedOrcaWorktrees,
  normalizeWorktreePath,
  setCachedOrcaWorktrees,
} from '../state/worktree-paths.ts'

let lastOrcaRefreshAt = 0
let orcaRefreshInFlight: Promise<void> | null = null

function resolveOrcaUserDataPath(homeDir = os.homedir()): string {
  if (process.env.ORCA_USER_DATA_PATH) return process.env.ORCA_USER_DATA_PATH
  if (process.platform === 'darwin') {
    return path.join(homeDir, 'Library', 'Application Support', 'orca')
  }
  return path.join(process.env.XDG_CONFIG_HOME || path.join(homeDir, '.config'), 'orca')
}

async function queryOrcaWorktreePsViaSocket(
  homeDir = os.homedir(),
  timeoutMs = 1200
): Promise<OrcaWorktreePsEntry[] | null> {
  const metadataPath = path.join(resolveOrcaUserDataPath(homeDir), 'orca-runtime.json')
  if (!fs.existsSync(metadataPath)) return null
  let metadata: {
    authToken?: string
    transports?: Array<{ kind?: string; endpoint?: string }>
    transport?: { kind?: string; endpoint?: string }
  }
  try {
    metadata = JSON.parse(fs.readFileSync(metadataPath, 'utf8'))
  } catch {
    return null
  }
  const transports = Array.isArray(metadata.transports)
    ? metadata.transports
    : metadata.transport
      ? [metadata.transport]
      : []
  const unixTransport = transports.find(t => t?.kind === 'unix' && t?.endpoint)
  if (!unixTransport?.endpoint || !metadata.authToken) return null

  return await new Promise<OrcaWorktreePsEntry[] | null>((resolve) => {
    const socket = net.createConnection(unixTransport.endpoint!)
    let buffer = ''
    let settled = false
    const reqId = crypto.randomUUID()

    const finish = (val: OrcaWorktreePsEntry[] | null) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      try { socket.destroy() } catch {}
      resolve(val)
    }

    const timer = setTimeout(() => finish(null), timeoutMs)
    timer.unref?.()

    socket.setEncoding('utf8')
    socket.once('error', () => finish(null))
    socket.once('close', () => finish(null))
    socket.on('data', (chunk: string) => {
      buffer += chunk
      let idx: number
      while ((idx = buffer.indexOf('\n')) !== -1) {
        const line = buffer.slice(0, idx).trim()
        buffer = buffer.slice(idx + 1)
        if (!line) continue
        try {
          const frame = JSON.parse(line)
          if (frame?._keepalive) continue
          if (frame?.id === reqId) {
            const wts = frame?.result?.worktrees
            finish(Array.isArray(wts) ? wts : null)
            return
          }
        } catch {
          finish(null)
          return
        }
      }
    })
    socket.once('connect', () => {
      try {
        socket.write(`${JSON.stringify({
          id: reqId,
          authToken: metadata.authToken,
          method: 'worktree.ps',
          params: { limit: 100 },
        })}\n`)
      } catch {
        finish(null)
      }
    })
  })
}

export async function refreshOrcaContextCache(homeDir = os.homedir()): Promise<void> {
  const now = Date.now()
  if (orcaRefreshInFlight) return orcaRefreshInFlight
  if (now - lastOrcaRefreshAt < 1500 && getCachedOrcaWorktrees().length > 0) return

  orcaRefreshInFlight = (async () => {
    try {
      const worktrees = await queryOrcaWorktreePsViaSocket(homeDir, 1200)
      if (worktrees && worktrees.length > 0) {
        setCachedOrcaWorktrees(worktrees)
        lastOrcaRefreshAt = Date.now()
        syncOrcaWorktreeLineage(worktrees, homeDir)
      }
    } catch {} finally {
      orcaRefreshInFlight = null
    }
  })()
  return orcaRefreshInFlight
}

function expectedWorkspaceSandboxPrefix(
  agent: 'claude' | 'codex' | 'antigravity',
  workspacePath: string
): string {
  const prefix = agent === 'claude' ? 'cc' : agent === 'codex' ? 'cx' : 'ag'
  const projectName = path.basename(workspacePath)
  const safeProj = projectName.replace(/[^a-zA-Z0-9_-]/g, '-').toLowerCase()
  const truncated = safeProj.slice(0, 8).replace(/^-+|-+$/g, '') || 'ws'
  return `${prefix}-${truncated.slice(0, 6)}-`
}

/**
 * Resolves ONLY the OpenShell sandbox running for the currently active tab in `selectedWorkspace`.
 * Never leaks sandboxes belonging to other repositories, background probes, or other tabs.
 */
export function resolveCurrentTabSandbox(params: {
  allSandboxes: ActiveSandboxInfo[]
  selectedWorkspace: WorkspaceEntry
  currentAgent: 'claude' | 'codex' | 'antigravity'
  activeAgentSessions: ActiveAgentSessionInfo[]
  homeDir?: string
}): ActiveSandboxInfo[] {
  const { allSandboxes, selectedWorkspace, currentAgent, activeAgentSessions } = params
  if (allSandboxes.length === 0) return []

  const registry = readSandboxRegistryMap(params.homeDir)
  const activeSession = activeAgentSessions[0] || null
  const activeAgentSessionId = extractAgentSessionIdFromPaneKey(activeSession?.paneKey)
  const activePaneKey = activeSession?.paneKey || null
  const activePanePrefix = activePaneKey && activePaneKey.includes(':')
    ? activePaneKey.split(':')[0]
    : activePaneKey

  // 1. Exact match by structured chat session ID (ORCA_AGENT_SESSION_ID)
  if (activeAgentSessionId) {
    const exactBySession = allSandboxes.find(
      sb => registry.get(sb.name)?.agentSessionId === activeAgentSessionId
    )
    if (exactBySession) return [exactBySession]
  }

  // 2. Exact match by terminal pane / handle ID (OPENSHELL_BRIDGE_TERMINAL_ID)
  if (activePaneKey) {
    const exactByTerminal = allSandboxes.find(sb => {
      const term = registry.get(sb.name)?.terminalId
      return Boolean(term && (term === activePaneKey || term === activePanePrefix))
    })
    if (exactByTerminal) return [exactByTerminal]
  }

  // 3. Fallback: match sandboxes owned by this workspace + currentAgent (excluding sandboxes bound to another tab)
  const normWsPath = normalizeWorktreePath(selectedWorkspace.path)
  const slugPrefix = expectedWorkspaceSandboxPrefix(currentAgent, normWsPath || selectedWorkspace.path)

  const workspaceMatches = allSandboxes.filter(sb => {
    if (sb.agent !== currentAgent) return false
    const meta = registry.get(sb.name)
    if (meta) {
      if (activeAgentSessionId && meta.agentSessionId && meta.agentSessionId !== activeAgentSessionId) {
        return false
      }
      if (activePaneKey && meta.terminalId && meta.terminalId !== activePaneKey && meta.terminalId !== activePanePrefix) {
        return false
      }
      const pathMatch = Boolean(meta.workspacePath && normalizeWorktreePath(meta.workspacePath) === normWsPath)
      const idMatch = Boolean(meta.workspaceId && meta.workspaceId === selectedWorkspace.id)
      return pathMatch || idMatch
    }
    return sb.name.startsWith(slugPrefix)
  })

  if (workspaceMatches.length === 0) return []
  workspaceMatches.sort((a, b) => String(b.created || '').localeCompare(String(a.created || '')))
  return [workspaceMatches[0]]
}

/**
 * Queries Orca for the currently active worktree and detects the currently running/active agent in that worktree.
 * Uses the non-blocking socket RPC cache so the Orca worker event loop is never blocked by synchronous CLI spawns.
 */
export function discoverCurrentOrcaContext(options?: {
  workspacePath?: string
  agent?: string
  fallbackAgent?: string
  homeDir?: string
}): CurrentOrcaContext {
  let activeWorkspace: WorkspaceEntry | null = null
  const activeAgentSessions: ActiveAgentSessionInfo[] = []
  let detectedAgent: 'claude' | 'codex' | 'antigravity' | null = normalizeAgentId(options?.agent)

  const isExplicitTestPath =
    Boolean(options?.workspacePath) &&
    (options!.workspacePath!.includes('openshell-policy-test-') || !fs.existsSync(path.join(options!.workspacePath!, '.git')))

  if (!isExplicitTestPath) {
    // Trigger background refresh for future calls without blocking
    void refreshOrcaContextCache(options?.homeDir)

    const worktrees = getCachedOrcaWorktrees()
    const normReqPath = options?.workspacePath ? normalizeWorktreePath(options.workspacePath) : ''
    const targetWt = normReqPath
      ? worktrees.find(w => normalizeWorktreePath(w.path) === normReqPath)
      : (worktrees.find(w => w.isActive) || worktrees[0])

    if (targetWt?.path) {
      activeWorkspace = {
        id: targetWt.worktreeId || `local::${targetWt.path}`,
        name: targetWt.repo || targetWt.displayName || path.basename(targetWt.path),
        path: targetWt.path,
        branch: targetWt.branch ? targetWt.branch.replace(/^refs\/heads\//, '') : null,
      }
      for (const ag of targetWt.agents ?? []) {
        const norm = normalizeAgentId(ag.agentType)
        if (norm) {
          activeAgentSessions.push({
            agent: norm,
            state: ag.state || 'unknown',
            conversationName: ag.conversationName || null,
            paneKey: ag.paneKey || null,
            updatedAt: Number(ag.updatedAt ?? 0),
          })
        }
      }
    }
  }

  if (!activeWorkspace) {
    const fallbackPath =
      (options?.workspacePath && fs.existsSync(options.workspacePath) ? options.workspacePath : null) ||
      process.cwd()
    activeWorkspace = {
      id: `local::${fallbackPath}`,
      name: path.basename(fallbackPath),
      path: fallbackPath,
      branch: null,
    }
  }

  // Sort active agent sessions: working/running first, then most recently updated
  activeAgentSessions.sort((a, b) => {
    const aWorking = a.state === 'working' || a.state === 'running' ? 1 : 0
    const bWorking = b.state === 'working' || b.state === 'running' ? 1 : 0
    if (aWorking !== bWorking) return bWorking - aWorking
    return b.updatedAt - a.updatedAt
  })

  if (!detectedAgent && activeAgentSessions.length > 0) {
    detectedAgent = activeAgentSessions[0].agent
  }

  if (!detectedAgent && options?.fallbackAgent) {
    detectedAgent = normalizeAgentId(options.fallbackAgent)
  }

  // Also check running OpenShell sandboxes if no agent session was found via worktree ps
  if (!detectedAgent) {
    const sandboxes = listActiveSandboxes()
    const sbAgent = sandboxes.map(s => normalizeAgentId(s.agent)).find(Boolean)
    if (sbAgent) detectedAgent = sbAgent
  }

  return {
    workspace: activeWorkspace,
    currentAgent: detectedAgent || 'antigravity',
    activeAgentSessions,
  }
}
