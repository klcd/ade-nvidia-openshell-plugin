import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import {
  extractAgentSessionIdFromPaneKey,
  normalizeAgentId,
  type OrcaWorktreePsEntry,
  type SandboxIdleTimeoutOptions,
  type SandboxModeFileData,
  type SandboxModeQueryOptions,
  type SandboxModeState,
} from '../types.ts'
import {
  readSandboxRegistryMap,
  removeSandboxRegistryEntryOnly,
} from './sandbox-registry.ts'
import {
  collectOrcaWorktreeParentMap,
  doesPathDescendFrom,
  getCachedOrcaWorktrees,
  normalizeWorktreePath,
  resolveGitMainWorktreePath,
  resolveWorkspacePathById,
} from './worktree-paths.ts'

export const DEFAULT_SANDBOX_IDLE_TIMEOUT_SEC = 300

export function getSandboxModeFilePath(homeDir = os.homedir()): string {
  if (process.env.ORCA_OPENSHELL_MODE_FILE) {
    return process.env.ORCA_OPENSHELL_MODE_FILE
  }
  return path.join(homeDir, '.config', 'orca-openshell', 'sandbox-mode.json')
}

export function syncOrcaWorktreeLineage(
  worktrees: OrcaWorktreePsEntry[],
  homeDir = os.homedir()
): void {
  const discovered = collectOrcaWorktreeParentMap(worktrees)
  if (Object.keys(discovered).length === 0) return
  const filePath = getSandboxModeFilePath(homeDir)
  try {
    let existing: SandboxModeFileData = {}
    if (fs.existsSync(filePath)) {
      existing = JSON.parse(fs.readFileSync(filePath, 'utf8')) as SandboxModeFileData
    }
    const prevParents = existing.parentPaths || {}
    let changed = false
    const mergedParents: Record<string, string> = { ...prevParents }
    for (const [childPath, parentPath] of Object.entries(discovered)) {
      if (mergedParents[childPath] !== parentPath) {
        mergedParents[childPath] = parentPath
        changed = true
      }
    }
    if (changed) {
      fs.mkdirSync(path.dirname(filePath), { recursive: true })
      fs.writeFileSync(
        filePath,
        JSON.stringify({ ...existing, parentPaths: mergedParents }, null, 2) + '\n',
        'utf8'
      )
    }
  } catch {}
}

export function getSandboxMode(
  optionsOrHomeDir?: SandboxModeQueryOptions | string,
  homeDirArg = os.homedir()
): SandboxModeState {
  const opts: SandboxModeQueryOptions =
    typeof optionsOrHomeDir === 'string' ? {} : (optionsOrHomeDir || {})
  const homeDir = typeof optionsOrHomeDir === 'string' ? optionsOrHomeDir : homeDirArg
  const filePath = getSandboxModeFilePath(homeDir)
  try {
    if (!fs.existsSync(filePath)) {
      return { enabled: true, updatedAt: null, inheritedFrom: null }
    }
    const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8')) as SandboxModeFileData
    const updatedAtFallback = typeof parsed.updatedAt === 'string' ? parsed.updatedAt : null
    if (!parsed.worktrees) {
      return {
        enabled: parsed.enabled !== false,
        updatedAt: updatedAtFallback,
        inheritedFrom: null,
      }
    }

    const worktreeMap = new Map<string, { enabled: boolean; updatedAt: string; workspaceId?: string }>()
    for (const [k, v] of Object.entries(parsed.worktrees)) {
      if (v && typeof v === 'object') {
        worktreeMap.set(normalizeWorktreePath(k), v)
      }
    }

    const parentMap = new Map<string, string>()
    for (const [k, v] of Object.entries(collectOrcaWorktreeParentMap(getCachedOrcaWorktrees()))) {
      parentMap.set(k, v)
    }
    for (const [k, v] of Object.entries(parsed.parentPaths || {})) {
      if (typeof v === 'string' && v) {
        parentMap.set(normalizeWorktreePath(k), normalizeWorktreePath(v))
      }
    }
    for (const [k, v] of Object.entries(opts.parentPaths || {})) {
      if (typeof v === 'string' && v) {
        parentMap.set(normalizeWorktreePath(k), normalizeWorktreePath(v))
      }
    }

    const resolvedRawPath = opts.workspacePath || resolveWorkspacePathById(opts.workspaceId) || ''
    const startPath = normalizeWorktreePath(resolvedRawPath)

    if (!startPath && opts.workspaceId) {
      for (const info of worktreeMap.values()) {
        if (info?.workspaceId === opts.workspaceId) {
          return {
            enabled: info.enabled !== false,
            updatedAt: typeof info.updatedAt === 'string' ? info.updatedAt : updatedAtFallback,
            inheritedFrom: null,
          }
        }
      }
      return { enabled: true, updatedAt: updatedAtFallback, inheritedFrom: null }
    }

    const visited = new Set<string>()
    let curr = startPath
    while (curr && !visited.has(curr)) {
      visited.add(curr)
      const direct = worktreeMap.get(curr)
      if (direct !== undefined) {
        return {
          enabled: direct.enabled !== false,
          updatedAt: typeof direct.updatedAt === 'string' ? direct.updatedAt : updatedAtFallback,
          inheritedFrom: curr === startPath ? null : curr,
        }
      }

      let nextParent = parentMap.get(curr) || resolveGitMainWorktreePath(curr) || ''
      let anc = path.dirname(curr)
      while (anc && anc !== curr && anc !== path.dirname(anc)) {
        const ancEntry = worktreeMap.get(anc)
        if (ancEntry !== undefined) {
          return {
            enabled: ancEntry.enabled !== false,
            updatedAt: typeof ancEntry.updatedAt === 'string' ? ancEntry.updatedAt : updatedAtFallback,
            inheritedFrom: anc,
          }
        }
        if (!nextParent) {
          nextParent = parentMap.get(anc) || resolveGitMainWorktreePath(anc) || ''
        }
        anc = path.dirname(anc)
      }

      if (nextParent && !visited.has(nextParent)) {
        curr = nextParent
        continue
      }
      break
    }

    return { enabled: true, updatedAt: updatedAtFallback, inheritedFrom: null }
  } catch {
    return { enabled: true, updatedAt: null, inheritedFrom: null }
  }
}

export function setSandboxMode(
  enabled: boolean,
  options?: SandboxModeQueryOptions,
  homeDir = os.homedir()
): SandboxModeState {
  const filePath = getSandboxModeFilePath(homeDir)
  const updatedAt = new Date().toISOString()
  let existing: SandboxModeFileData = {}
  try {
    if (fs.existsSync(filePath)) {
      existing = JSON.parse(fs.readFileSync(filePath, 'utf8')) as SandboxModeFileData
    }
  } catch {}

  const worktrees: Record<string, { enabled: boolean; updatedAt: string; workspaceId?: string }> = {}
  for (const [k, v] of Object.entries(existing.worktrees || {})) {
    if (v && typeof v === 'object') {
      worktrees[normalizeWorktreePath(k)] = v
    }
  }

  const parentPaths: Record<string, string> = {}
  for (const [k, v] of Object.entries(collectOrcaWorktreeParentMap(getCachedOrcaWorktrees()))) {
    parentPaths[k] = v
  }
  for (const [k, v] of Object.entries(existing.parentPaths || {})) {
    if (typeof v === 'string' && v) {
      parentPaths[normalizeWorktreePath(k)] = normalizeWorktreePath(v)
    }
  }
  for (const [k, v] of Object.entries(options?.parentPaths || {})) {
    if (typeof v === 'string' && v) {
      parentPaths[normalizeWorktreePath(k)] = normalizeWorktreePath(v)
    }
  }

  const targetRaw = options?.workspacePath || resolveWorkspacePathById(options?.workspaceId) || process.cwd()
  const targetKey = normalizeWorktreePath(targetRaw)

  // Propagate parent setting to existing child workspaces by clearing stale child overrides
  const parentMap = new Map<string, string>(Object.entries(parentPaths))
  for (const existingKey of Object.keys(worktrees)) {
    if (existingKey !== targetKey && doesPathDescendFrom(existingKey, targetKey, parentMap)) {
      delete worktrees[existingKey]
    }
  }

  worktrees[targetKey] = {
    enabled: Boolean(enabled),
    updatedAt,
    ...(options?.workspaceId ? { workspaceId: options.workspaceId } : {}),
  }

  const nextData: SandboxModeFileData = {
    updatedAt,
    ...(existing.tabIdleTimeouts && Object.keys(existing.tabIdleTimeouts).length > 0
      ? { tabIdleTimeouts: existing.tabIdleTimeouts }
      : {}),
    worktrees,
    ...(Object.keys(parentPaths).length > 0 ? { parentPaths } : {}),
  }

  fs.mkdirSync(path.dirname(filePath), { recursive: true })
  fs.writeFileSync(filePath, JSON.stringify(nextData, null, 2) + '\n', 'utf8')
  return getSandboxMode(
    { workspacePath: targetKey, workspaceId: options?.workspaceId, parentPaths },
    homeDir
  )
}

function resolveTabIdleTimeoutKeys(
  options?: SandboxIdleTimeoutOptions,
  homeDir = os.homedir(),
  useEnvFallback = false
): string[] {
  const sbName = String(options?.sandboxName || '').trim()
  let sessId = String(
    options?.agentSessionId ||
      extractAgentSessionIdFromPaneKey(options?.paneKey) ||
      (useEnvFallback ? process.env.ORCA_AGENT_SESSION_ID || '' : '')
  ).trim()
  const rawTerm = String(
    options?.terminalId ||
      options?.paneKey ||
      (useEnvFallback
        ? process.env.OPENSHELL_BRIDGE_TERMINAL_ID || process.env.ORCA_TERMINAL_HANDLE || ''
        : '')
  ).trim()
  let termPrefix = rawTerm.includes(':') ? rawTerm.split(':')[0] : rawTerm

  if (sbName) {
    const regMeta = readSandboxRegistryMap(homeDir).get(sbName)
    if (!sessId && regMeta?.agentSessionId) {
      sessId = regMeta.agentSessionId.trim()
    }
    if (!termPrefix && regMeta?.terminalId) {
      termPrefix = regMeta.terminalId.includes(':')
        ? regMeta.terminalId.split(':')[0]
        : regMeta.terminalId
    }
  }

  const keys: string[] = []
  if (sbName) keys.push(`sandbox:${sbName}`)
  if (sessId) keys.push(`session:${sessId}`)
  if (termPrefix) keys.push(`terminal:${termPrefix}`)

  if (keys.length === 0 && options?.workspacePath) {
    const normWs = normalizeWorktreePath(options.workspacePath)
    const normAgent = normalizeAgentId(options.agent || undefined) || 'default'
    if (normWs) {
      keys.push(`unassigned:${normWs}:${normAgent}`)
    }
  }
  return keys
}

export function getSandboxIdleTimeoutSeconds(
  optionsOrHomeDir?: SandboxIdleTimeoutOptions | string,
  homeDirArg = os.homedir(),
  useEnvFallback = false
): number {
  const envVal = process.env.ORCA_SANDBOX_IDLE_TIMEOUT_SEC
  if (envVal !== undefined && envVal.trim() !== '') {
    const parsedEnv = Number(envVal)
    if (Number.isFinite(parsedEnv) && parsedEnv >= 0) {
      return Math.floor(parsedEnv)
    }
  }
  const opts: SandboxIdleTimeoutOptions =
    typeof optionsOrHomeDir === 'string' ? {} : (optionsOrHomeDir || {})
  const homeDir = typeof optionsOrHomeDir === 'string' ? optionsOrHomeDir : homeDirArg
  const filePath = getSandboxModeFilePath(homeDir)
  try {
    if (!fs.existsSync(filePath)) return DEFAULT_SANDBOX_IDLE_TIMEOUT_SEC
    const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8')) as SandboxModeFileData
    const tabMap = parsed.tabIdleTimeouts
    if (tabMap && typeof tabMap === 'object') {
      const candidateKeys = resolveTabIdleTimeoutKeys(opts, homeDir, useEnvFallback)
      for (const key of candidateKeys) {
        const entry = tabMap[key]
        if (
          entry &&
          typeof entry.seconds === 'number' &&
          Number.isFinite(entry.seconds) &&
          entry.seconds >= 0
        ) {
          return Math.floor(entry.seconds)
        }
      }
    }
  } catch {}
  return DEFAULT_SANDBOX_IDLE_TIMEOUT_SEC
}

export function setSandboxIdleTimeoutSeconds(
  seconds: number,
  optionsOrHomeDir?: SandboxIdleTimeoutOptions | string,
  homeDirArg = os.homedir()
): number {
  const normalized =
    Number.isFinite(seconds) && seconds >= 0 ? Math.floor(seconds) : DEFAULT_SANDBOX_IDLE_TIMEOUT_SEC
  const opts: SandboxIdleTimeoutOptions =
    typeof optionsOrHomeDir === 'string' ? {} : (optionsOrHomeDir || {})
  const homeDir = typeof optionsOrHomeDir === 'string' ? optionsOrHomeDir : homeDirArg
  const filePath = getSandboxModeFilePath(homeDir)
  let existing: SandboxModeFileData = {}
  try {
    if (fs.existsSync(filePath)) {
      existing = JSON.parse(fs.readFileSync(filePath, 'utf8')) as SandboxModeFileData
    }
  } catch {}

  const updatedAt = new Date().toISOString()
  const tabIdleTimeouts: Record<string, { seconds: number; updatedAt: string }> = {
    ...(existing.tabIdleTimeouts || {}),
  }
  const keys = resolveTabIdleTimeoutKeys(opts, homeDir)
  const targetKeys = keys.length > 0 ? keys : ['unassigned:default']
  for (const key of targetKeys) {
    tabIdleTimeouts[key] = { seconds: normalized, updatedAt }
  }

  const { idleTimeoutSeconds: _legacyGlobalTimeout, ...restExisting } = existing
  const nextData: SandboxModeFileData = {
    ...restExisting,
    updatedAt,
    tabIdleTimeouts,
  }
  fs.mkdirSync(path.dirname(filePath), { recursive: true })
  fs.writeFileSync(filePath, JSON.stringify(nextData, null, 2) + '\n', 'utf8')
  return normalized
}

export function pruneSandboxIdleTimeout(sandboxName: string, homeDir = os.homedir()): void {
  if (!sandboxName) return
  const filePath = getSandboxModeFilePath(homeDir)
  try {
    if (!fs.existsSync(filePath)) return
    const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8')) as SandboxModeFileData
    const sbKey = `sandbox:${sandboxName}`
    if (parsed?.tabIdleTimeouts && sbKey in parsed.tabIdleTimeouts) {
      delete parsed.tabIdleTimeouts[sbKey]
      const tmpMode = `${filePath}.${process.pid}.tmp`
      fs.writeFileSync(tmpMode, JSON.stringify(parsed, null, 2) + '\n', 'utf8')
      fs.renameSync(tmpMode, filePath)
    }
  } catch {}
}

export function pruneSandboxRegistryEntry(sandboxName: string, homeDir = os.homedir()): void {
  if (!sandboxName) return
  pruneSandboxIdleTimeout(sandboxName, homeDir)
  removeSandboxRegistryEntryOnly(sandboxName, homeDir)
}
