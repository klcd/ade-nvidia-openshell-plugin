import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { inferSandboxAgent, type SandboxRegistryEntry } from '../types.ts'
import { extractPathFromWorkspaceId, normalizeWorktreePath } from './worktree-paths.ts'

export function getSandboxRegistryFilePath(homeDir = os.homedir()): string {
  if (process.env.ORCA_OPENSHELL_REGISTRY_FILE) {
    return process.env.ORCA_OPENSHELL_REGISTRY_FILE
  }
  return path.join(homeDir, '.config', 'orca-openshell', 'sandbox-registry.json')
}

export function isHostPidAlive(pid?: number): boolean {
  if (pid === undefined || pid === null || pid <= 0) return true
  if (!Number.isFinite(pid) || pid <= 1) return false
  try {
    process.kill(pid, 0)
    return true
  } catch {
    return false
  }
}

export function registerSandboxRegistryEntry(
  entry: Omit<SandboxRegistryEntry, 'createdAt' | 'updatedAt'> & {
    createdAt?: string
    updatedAt?: string
  },
  homeDir = os.homedir()
): void {
  const regPath = getSandboxRegistryFilePath(homeDir)
  try {
    fs.mkdirSync(path.dirname(regPath), { recursive: true })
    let existing: SandboxRegistryEntry[] = []
    if (fs.existsSync(regPath)) {
      try {
        const parsed = JSON.parse(fs.readFileSync(regPath, 'utf8')) as {
          entries?: SandboxRegistryEntry[]
        }
        if (Array.isArray(parsed?.entries)) {
          existing = parsed.entries
        }
      } catch {}
    }

    const now = new Date().toISOString()
    const normalizedPath = normalizeWorktreePath(entry.workspacePath)
    const alive = existing.filter(
      e =>
        e &&
        typeof e.sandboxName === 'string' &&
        e.sandboxName !== entry.sandboxName &&
        isHostPidAlive(e.pid)
    )
    const prev = existing.find(e => e?.sandboxName === entry.sandboxName)
    alive.push({
      sandboxName: entry.sandboxName,
      agent: entry.agent,
      workspacePath: normalizedPath,
      ...(entry.workspaceId ? { workspaceId: entry.workspaceId } : {}),
      ...(entry.terminalId ? { terminalId: entry.terminalId } : {}),
      ...(entry.agentSessionId ? { agentSessionId: entry.agentSessionId } : {}),
      ...(entry.pid ? { pid: entry.pid } : {}),
      createdAt: entry.createdAt || prev?.createdAt || now,
      updatedAt: entry.updatedAt || now,
    })

    const tmpPath = `${regPath}.${process.pid}.tmp`
    fs.writeFileSync(tmpPath, JSON.stringify({ entries: alive }, null, 2) + '\n', 'utf8')
    fs.renameSync(tmpPath, regPath)
  } catch {}
}

export function removeSandboxRegistryEntryOnly(sandboxName: string, homeDir = os.homedir()): void {
  if (!sandboxName) return
  const regPath = getSandboxRegistryFilePath(homeDir)
  try {
    if (!fs.existsSync(regPath)) return
    const parsed = JSON.parse(fs.readFileSync(regPath, 'utf8')) as { entries?: SandboxRegistryEntry[] }
    if (!Array.isArray(parsed?.entries)) return
    const filtered = parsed.entries.filter(e => e?.sandboxName && e.sandboxName !== sandboxName)
    if (filtered.length !== parsed.entries.length) {
      const tmpPath = `${regPath}.${process.pid}.tmp`
      fs.writeFileSync(tmpPath, JSON.stringify({ entries: filtered }, null, 2) + '\n', 'utf8')
      fs.renameSync(tmpPath, regPath)
    }
  } catch {}
}

export function readSandboxRegistryMap(homeDir = os.homedir()): Map<string, SandboxRegistryEntry> {
  const map = new Map<string, SandboxRegistryEntry>()
  const regPath = getSandboxRegistryFilePath(homeDir)
  try {
    if (fs.existsSync(regPath)) {
      const parsed = JSON.parse(fs.readFileSync(regPath, 'utf8')) as { entries?: SandboxRegistryEntry[] }
      for (const entry of parsed?.entries ?? []) {
        if (entry?.sandboxName && isHostPidAlive(entry.pid)) {
          map.set(entry.sandboxName, entry)
        }
      }
    }
  } catch {}

  const launchesDir = path.join(homeDir, '.agents', 'orca-openshell-delegation', 'launches')
  try {
    if (fs.existsSync(launchesDir)) {
      for (const file of fs.readdirSync(launchesDir)) {
        if (!file.endsWith('.json')) continue
        try {
          const data = JSON.parse(fs.readFileSync(path.join(launchesDir, file), 'utf8')) as {
            terminal?: string
            workspace?: string
            sandbox?: string
          }
          if (!data?.sandbox) continue
          const existing = map.get(data.sandbox)
          if (existing) {
            if (!existing.terminalId && data.terminal) existing.terminalId = data.terminal
            if (!existing.workspaceId && data.workspace) existing.workspaceId = data.workspace
          } else {
            const wsPath = extractPathFromWorkspaceId(data.workspace) || ''
            const inferred = inferSandboxAgent(data.sandbox)
            if (inferred === 'claude' || inferred === 'codex' || inferred === 'antigravity') {
              map.set(data.sandbox, {
                sandboxName: data.sandbox,
                agent: inferred,
                workspacePath: wsPath,
                ...(data.workspace ? { workspaceId: data.workspace } : {}),
                ...(data.terminal ? { terminalId: data.terminal } : {}),
              })
            }
          }
        } catch {}
      }
    }
  } catch {}

  if (!process.env.ORCA_OPENSHELL_REGISTRY_FILE) {
    try {
      const agSessionsRoot = process.env.ORCA_AG_SESSIONS_DIR || path.join(homeDir, '.orca', 'ag')
      const agBases: string[] = []
      if (fs.existsSync(agSessionsRoot)) {
        agBases.push(agSessionsRoot)
      }
      for (const rootDir of ['/tmp', '/private/tmp']) {
        if (!fs.existsSync(rootDir)) continue
        for (const agBase of fs.readdirSync(rootDir)) {
          if (agBase.startsWith('orca-ag-openshell-')) {
            agBases.push(path.join(rootDir, agBase))
          }
        }
      }
      for (const fullBase of agBases) {
        for (const sessKey of fs.readdirSync(fullBase)) {
          const stateFile = path.join(fullBase, sessKey, 'state.json')
          if (!fs.existsSync(stateFile)) continue
          try {
            const st = JSON.parse(fs.readFileSync(stateFile, 'utf8')) as {
              sandboxName?: string
              projectRoot?: string
              daemonPid?: number
              agentSessionId?: string
            }
            if (st?.sandboxName && !map.has(st.sandboxName) && isHostPidAlive(st.daemonPid)) {
              const resolvedSessId =
                st.agentSessionId || (sessKey.startsWith('antigravity_') ? sessKey : undefined)
              map.set(st.sandboxName, {
                sandboxName: st.sandboxName,
                agent: 'antigravity',
                workspacePath: st.projectRoot || '',
                ...(resolvedSessId ? { agentSessionId: resolvedSessId } : {}),
                pid: st.daemonPid,
              })
            }
          } catch {}
        }
      }
    } catch {}
  }

  return map
}
