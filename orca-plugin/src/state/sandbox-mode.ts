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
import { readJsonSafe, withStateLock, writeJsonAtomic } from './file-lock.ts'
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

export const DEFAULT_SANDBOX_ENABLED = false
export const DEFAULT_SANDBOX_IDLE_TIMEOUT_SEC = 300

export function getSandboxModeFilePath(homeDir = os.homedir()): string {
  if (process.env.ORCA_OPENSHELL_MODE_FILE) {
    return process.env.ORCA_OPENSHELL_MODE_FILE
  }
  return path.join(homeDir, '.config', 'orca-openshell', 'sandbox-mode.json')
}

function resolveEnvDefaultSandboxEnabled(): boolean | undefined {
  const raw = process.env.ORCA_OPENSHELL_DEFAULT_ENABLED
  if (raw === undefined || raw.trim() === '') return undefined
  const lower = raw.trim().toLowerCase()
  if (lower === '1' || lower === 'true' || lower === 'on' || lower === 'yes') return true
  if (lower === '0' || lower === 'false' || lower === 'off' || lower === 'no') return false
  return undefined
}

export function getDefaultSandboxEnabled(homeDir = os.homedir()): boolean {
  const envVal = resolveEnvDefaultSandboxEnabled()
  if (envVal !== undefined) return envVal
  const filePath = getSandboxModeFilePath(homeDir)
  if (!fs.existsSync(filePath)) return DEFAULT_SANDBOX_ENABLED
  const parsed = readJsonSafe<SandboxModeFileData>(filePath, {})
  if (typeof parsed.defaultEnabled === 'boolean') {
    return parsed.defaultEnabled
  }
  if (!parsed.worktrees && typeof parsed.enabled === 'boolean') {
    return parsed.enabled
  }
  return DEFAULT_SANDBOX_ENABLED
}

export function setDefaultSandboxEnabled(enabled: boolean, homeDir = os.homedir()): boolean {
  const filePath = getSandboxModeFilePath(homeDir)
  const normalized = Boolean(enabled)
  withStateLock(filePath, () => {
    const existing = readJsonSafe<SandboxModeFileData>(filePath, {})
    const nextData: SandboxModeFileData = {
      ...existing,
      defaultEnabled: normalized,
      updatedAt: new Date().toISOString(),
    }
    writeJsonAtomic(filePath, nextData)
  })
  return normalized
}

export function syncOrcaWorktreeLineage(
  worktrees: OrcaWorktreePsEntry[],
  homeDir = os.homedir()
): void {
  const discovered = collectOrcaWorktreeParentMap(worktrees)
  if (Object.keys(discovered).length === 0) return
  const filePath = getSandboxModeFilePath(homeDir)
  try {
    withStateLock(filePath, () => {
      const existing = readJsonSafe<SandboxModeFileData>(filePath, {})
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
        writeJsonAtomic(filePath, { ...existing, parentPaths: mergedParents })
      }
    })
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
  const fallbackDefault = resolveEnvDefaultSandboxEnabled() ?? DEFAULT_SANDBOX_ENABLED
  try {
    if (!fs.existsSync(filePath)) {
      return { enabled: fallbackDefault, updatedAt: null, inheritedFrom: null }
    }
    const parsed = readJsonSafe<SandboxModeFileData>(filePath, {})
    const updatedAtFallback = typeof parsed.updatedAt === 'string' ? parsed.updatedAt : null
    const defaultEnabled =
      resolveEnvDefaultSandboxEnabled() ??
      (typeof parsed.defaultEnabled === 'boolean'
        ? parsed.defaultEnabled
        : typeof parsed.enabled === 'boolean'
          ? parsed.enabled
          : DEFAULT_SANDBOX_ENABLED)
    if (!parsed.worktrees) {
      return {
        enabled: defaultEnabled,
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
      return { enabled: defaultEnabled, updatedAt: updatedAtFallback, inheritedFrom: null }
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

    return { enabled: defaultEnabled, updatedAt: updatedAtFallback, inheritedFrom: null }
  } catch {
    return { enabled: fallbackDefault, updatedAt: null, inheritedFrom: null }
  }
}

export function setSandboxMode(
  enabled: boolean,
  options?: SandboxModeQueryOptions,
  homeDir = os.homedir()
): SandboxModeState {
  const filePath = getSandboxModeFilePath(homeDir)
  const updatedAt = new Date().toISOString()
  let targetKey = ''
  let parentPaths: Record<string, string> = {}

  withStateLock(filePath, () => {
    const existing = readJsonSafe<SandboxModeFileData>(filePath, {})

    const worktrees: Record<string, { enabled: boolean; updatedAt: string; workspaceId?: string }> = {}
    for (const [k, v] of Object.entries(existing.worktrees || {})) {
      if (v && typeof v === 'object') {
        worktrees[normalizeWorktreePath(k)] = v
      }
    }

    parentPaths = {}
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
    targetKey = normalizeWorktreePath(targetRaw)

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
      ...(typeof existing.defaultEnabled === 'boolean' ? { defaultEnabled: existing.defaultEnabled } : {}),
      ...(existing.tabIdleTimeouts && Object.keys(existing.tabIdleTimeouts).length > 0
        ? { tabIdleTimeouts: existing.tabIdleTimeouts }
        : {}),
      worktrees,
      ...(Object.keys(parentPaths).length > 0 ? { parentPaths } : {}),
    }

    writeJsonAtomic(filePath, nextData)
  })

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
    const parsed = readJsonSafe<SandboxModeFileData>(filePath, {})
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
  const keys = resolveTabIdleTimeoutKeys(opts, homeDir)
  const targetKeys = keys.length > 0 ? keys : ['unassigned:default']

  withStateLock(filePath, () => {
    const existing = readJsonSafe<SandboxModeFileData>(filePath, {})
    const updatedAt = new Date().toISOString()
    const tabIdleTimeouts: Record<string, { seconds: number; updatedAt: string }> = {
      ...(existing.tabIdleTimeouts || {}),
    }
    for (const key of targetKeys) {
      tabIdleTimeouts[key] = { seconds: normalized, updatedAt }
    }

    const { idleTimeoutSeconds: _legacyGlobalTimeout, ...restExisting } = existing
    const nextData: SandboxModeFileData = {
      ...restExisting,
      updatedAt,
      tabIdleTimeouts,
    }
    writeJsonAtomic(filePath, nextData)
  })
  return normalized
}

export function pruneSandboxIdleTimeout(sandboxName: string, homeDir = os.homedir()): void {
  if (!sandboxName) return
  const filePath = getSandboxModeFilePath(homeDir)
  try {
    if (!fs.existsSync(filePath)) return
    withStateLock(filePath, () => {
      const parsed = readJsonSafe<SandboxModeFileData>(filePath, {})
      const sbKey = `sandbox:${sandboxName}`
      if (parsed?.tabIdleTimeouts && sbKey in parsed.tabIdleTimeouts) {
        delete parsed.tabIdleTimeouts[sbKey]
        writeJsonAtomic(filePath, parsed)
      }
    })
  } catch {}
}

export function pruneSandboxRegistryEntry(sandboxName: string, homeDir = os.homedir()): void {
  if (!sandboxName) return
  pruneSandboxIdleTimeout(sandboxName, homeDir)
  removeSandboxRegistryEntryOnly(sandboxName, homeDir)
}
