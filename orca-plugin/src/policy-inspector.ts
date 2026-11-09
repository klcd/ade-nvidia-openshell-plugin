import { execFile, execFileSync } from 'node:child_process'
import crypto from 'node:crypto'
import fs from 'node:fs'
import net from 'node:net'
import os from 'node:os'
import path from 'node:path'

export interface CliPermissionRule {
  raw: string
  tool: string
  pattern: string
  cliCommand: string
  baseBinary: string
  action: 'allow' | 'ask' | 'deny'
  scope: 'global' | 'workspace'
  groupName: string
  groupDescription: string
  sourceFile: string
  explanation: string
  compatibleAgents: string[]
}

export interface PermissionGroupSummary {
  name: string
  description: string
  scope: 'global' | 'workspace'
  sourceFile: string
  allowCount: number
  askCount: number
  denyCount: number
  rules: CliPermissionRule[]
}

export interface L7HttpRule {
  action: 'allow' | 'deny'
  method: string
  path: string
}

export interface NetworkEndpointRule {
  policyName: string
  source: string
  sourcePath?: string
  ruleScope?: 'temporary' | 'project' | 'global' | 'profile'
  temporary?: boolean
  host: string
  port: number
  protocol: string
  access: string
  enforcement: string
  binaries: string[]
  compatibleCliCommands: string[]
  triggerSource: string
  triggerExplanation: string
  l7Rules?: L7HttpRule[]
}

export interface AgentProfilePolicy {
  agent: 'claude' | 'codex' | 'antigravity'
  displayName: string
  hostWrapper: string
  hostWrapperInstalled: boolean
  containerImage: string
  providerProfile: string
  surfaces: Array<{ surface: string; transport: string; cliExample: string }>
  credentialPlaceholders: string[]
  allowedBinaries: string[]
  landlockMode: string
  filesystemReadWrite: string[]
  filesystemReadOnly: string[]
  endpoints: NetworkEndpointRule[]
}

export interface DelegationPolicySummary {
  autoGrantEnabled: boolean
  configPath: string | null
  allowedAgents: string[]
  maxWorkers: number
  maxDepth: number
  activeGrants: Array<{
    terminal: string
    workspace: string
    agents: string[]
    depth: number
    maxDepth: number
    maxWorkers: number
    remainingWorkers: number
  }>
  allowedCliCommands: Array<{
    command: string
    description: string
  }>
  blockedFlags: string[]
}

export interface NativeAgentSyncStatus {
  claudeSettingsPath: string
  claudeSynced: boolean
  claudeAllowCount: number
  claudeDenyCount: number
  codexRulesPath: string
  codexSynced: boolean
  codexRuleCount: number
  geminiSettingsPath: string
  geminiSynced: boolean
  geminiAllowCount: number
  geminiDenyCount: number
}

export interface ActiveSandboxInfo {
  name: string
  created: string
  phase: string
  agent: string
}

export interface WorkspaceEntry {
  id: string
  name: string
  path: string
  branch: string | null
}

export interface ActiveAgentSessionInfo {
  agent: 'claude' | 'codex' | 'antigravity'
  state: string
  conversationName: string | null
  paneKey: string | null
  updatedAt: number
}

export interface SandboxModeState {
  enabled: boolean
  updatedAt: string | null
  inheritedFrom: string | null
}

export interface PolicyInspectionReport {
  generatedAt: string
  sandboxEnabled: boolean
  sandboxInheritedFrom: string | null
  sandboxIdleTimeoutSeconds: number
  selectedWorkspace: WorkspaceEntry
  currentAgent: 'claude' | 'codex' | 'antigravity'
  activeAgentSessions: ActiveAgentSessionInfo[]
  workspaces: WorkspaceEntry[]
  activeSandboxes: ActiveSandboxInfo[]
  agents: AgentProfilePolicy[]
  permissionGroups: PermissionGroupSummary[]
  allCliRules: CliPermissionRule[]
  delegation: DelegationPolicySummary
  nativeSync: NativeAgentSyncStatus
}

interface OrcaWorktreePsEntry {
  worktreeId?: string
  worktreeInstanceId?: string
  parentWorktreeId?: string | null
  childWorktreeIds?: string[]
  isMainWorktree?: boolean
  path?: string
  repo?: string
  displayName?: string
  branch?: string | null
  isActive?: boolean
  agents?: Array<{
    paneKey?: string | null
    state?: string
    agentType?: string
    conversationName?: string | null
    updatedAt?: number
  }>
}

let cachedOrcaWorktrees: OrcaWorktreePsEntry[] = []
let lastOrcaRefreshAt = 0
let orcaRefreshInFlight: Promise<void> | null = null

interface SandboxModeFileData {
  enabled?: boolean
  updatedAt?: string
  idleTimeoutSeconds?: number
  tabIdleTimeouts?: Record<string, { seconds: number; updatedAt: string }>
  worktrees?: Record<string, { enabled: boolean; updatedAt: string; workspaceId?: string }>
  parentPaths?: Record<string, string>
}

export function normalizeWorktreePath(rawPath?: string | null): string {
  if (!rawPath) return ''
  try {
    return fs.existsSync(rawPath) ? fs.realpathSync(rawPath) : path.resolve(rawPath)
  } catch {
    return path.resolve(rawPath)
  }
}

export function resolveGitMainWorktreePath(dirPath: string): string | null {
  try {
    const dotGit = path.join(dirPath, '.git')
    if (!fs.existsSync(dotGit)) return null
    const stat = fs.lstatSync(dotGit)
    if (!stat.isFile()) return null
    const content = fs.readFileSync(dotGit, 'utf8').trim()
    if (!content.startsWith('gitdir:')) return null
    const rawGitDir = content.slice('gitdir:'.length).trim()
    const absGitDir = path.resolve(dirPath, rawGitDir)
    const worktreesSegment = `${path.sep}.git${path.sep}worktrees${path.sep}`
    const idx = absGitDir.indexOf(worktreesSegment)
    if (idx > 0) {
      return normalizeWorktreePath(absGitDir.slice(0, idx))
    }
    return null
  } catch {
    return null
  }
}

function extractPathFromWorkspaceId(workspaceId?: string | null): string {
  if (!workspaceId) return ''
  const sepIdx = workspaceId.indexOf('::/')
  if (sepIdx >= 0) {
    return workspaceId.slice(sepIdx + 2)
  }
  return ''
}

export function resolveWorkspacePathById(workspaceId?: string | null): string | undefined {
  if (!workspaceId) return undefined
  const fromId = extractPathFromWorkspaceId(workspaceId)
  if (fromId) return fromId
  for (const w of cachedOrcaWorktrees) {
    if (!w.path) continue
    if (
      w.worktreeId === workspaceId ||
      w.worktreeInstanceId === workspaceId ||
      (w.worktreeInstanceId && `wt2:local:${w.worktreeInstanceId}` === workspaceId)
    ) {
      return w.path
    }
  }
  return undefined
}

function collectOrcaWorktreeParentMap(worktrees: OrcaWorktreePsEntry[]): Record<string, string> {
  const byId = new Map<string, string>()
  for (const w of worktrees) {
    if (!w.path) continue
    const norm = normalizeWorktreePath(w.path)
    if (w.worktreeId) byId.set(w.worktreeId, norm)
    if (w.worktreeInstanceId) {
      byId.set(w.worktreeInstanceId, norm)
      byId.set(`wt2:local:${w.worktreeInstanceId}`, norm)
    }
  }
  const parents: Record<string, string> = {}
  for (const w of worktrees) {
    if (!w.path) continue
    const normPath = normalizeWorktreePath(w.path)
    if (w.parentWorktreeId) {
      const parentRaw = byId.get(w.parentWorktreeId) || extractPathFromWorkspaceId(w.parentWorktreeId)
      const normParent = normalizeWorktreePath(parentRaw)
      if (normParent && normParent !== normPath) {
        parents[normPath] = normParent
      }
    }
    for (const childId of w.childWorktreeIds ?? []) {
      const childRaw = byId.get(childId) || extractPathFromWorkspaceId(childId)
      const normChild = normalizeWorktreePath(childRaw)
      if (normChild && normChild !== normPath) {
        parents[normChild] = normPath
      }
    }
  }
  return parents
}

function syncOrcaWorktreeLineage(worktrees: OrcaWorktreePsEntry[], homeDir = os.homedir()): void {
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

function doesPathDescendFrom(
  candidatePath: string,
  targetAncestor: string,
  parentMap: Map<string, string>
): boolean {
  const visited = new Set<string>()
  let curr = normalizeWorktreePath(candidatePath)
  const normAncestor = normalizeWorktreePath(targetAncestor)
  if (!curr || !normAncestor || curr === normAncestor) return false

  while (curr && !visited.has(curr)) {
    visited.add(curr)
    if (curr === normAncestor) return true
    if (curr.startsWith(normAncestor + path.sep)) return true

    let nextParent = parentMap.get(curr) || resolveGitMainWorktreePath(curr) || ''
    let anc = path.dirname(curr)
    while (anc && anc !== curr && anc !== path.dirname(anc)) {
      if (anc === normAncestor) return true
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
  return false
}

export interface SandboxModeQueryOptions {
  workspacePath?: string
  workspaceId?: string
  parentPaths?: Record<string, string>
}

export function getSandboxModeFilePath(homeDir = os.homedir()): string {
  if (process.env.ORCA_OPENSHELL_MODE_FILE) {
    return process.env.ORCA_OPENSHELL_MODE_FILE
  }
  return path.join(homeDir, '.config', 'orca-openshell', 'sandbox-mode.json')
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
    for (const [k, v] of Object.entries(collectOrcaWorktreeParentMap(cachedOrcaWorktrees))) {
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
  for (const [k, v] of Object.entries(collectOrcaWorktreeParentMap(cachedOrcaWorktrees))) {
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

export const DEFAULT_SANDBOX_IDLE_TIMEOUT_SEC = 300

export interface SandboxIdleTimeoutOptions {
  sandboxName?: string | null
  agentSessionId?: string | null
  terminalId?: string | null
  paneKey?: string | null
  workspacePath?: string | null
  agent?: string | null
}

function resolveTabIdleTimeoutKeys(
  options?: SandboxIdleTimeoutOptions,
  homeDir = os.homedir()
): string[] {
  const sbName = String(options?.sandboxName || '').trim()
  let sessId = String(
    options?.agentSessionId || extractAgentSessionIdFromPaneKey(options?.paneKey) || ''
  ).trim()
  const rawTerm = String(options?.terminalId || options?.paneKey || '').trim()
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
  homeDirArg = os.homedir()
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
      const candidateKeys = resolveTabIdleTimeoutKeys(opts, homeDir)
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
      fs.writeFileSync(filePath, JSON.stringify(parsed, null, 2) + '\n', 'utf8')
    }
  } catch {}
}

export interface SessionEgressEntry {
  sandboxName?: string
  workspacePath: string
  agent: 'claude' | 'codex' | 'antigravity'
  ruleName: string
  host: string
  port: number
  action: 'allow' | 'deny'
  method: string
  path: string
  binary: string
  triggerCommand?: string
  createdAt: string
}

export function getSessionEgressFilePath(homeDir = os.homedir()): string {
  if (process.env.ORCA_OPENSHELL_SESSION_EGRESS_FILE) {
    return process.env.ORCA_OPENSHELL_SESSION_EGRESS_FILE
  }
  return path.join(homeDir, '.config', 'orca-openshell', 'session-egress.json')
}

export function readSessionEgressEntries(homeDir = os.homedir()): SessionEgressEntry[] {
  const filePath = getSessionEgressFilePath(homeDir)
  try {
    if (!fs.existsSync(filePath)) return []
    const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8')) as { entries?: SessionEgressEntry[] }
    return Array.isArray(parsed?.entries) ? parsed.entries : []
  } catch {
    return []
  }
}

export function writeSessionEgressEntries(entries: SessionEgressEntry[], homeDir = os.homedir()): void {
  const filePath = getSessionEgressFilePath(homeDir)
  fs.mkdirSync(path.dirname(filePath), { recursive: true })
  fs.writeFileSync(filePath, JSON.stringify({ entries }, null, 2) + '\n', 'utf8')
}

export function recordSessionEgressRule(entry: SessionEgressEntry, homeDir = os.homedir()): void {
  const entries = readSessionEgressEntries(homeDir)
  const normHost = entry.host.toLowerCase()
  const idx = entries.findIndex(
    e =>
      (e.sandboxName || '') === (entry.sandboxName || '') &&
      e.workspacePath === entry.workspacePath &&
      e.agent === entry.agent &&
      e.host.toLowerCase() === normHost &&
      e.port === entry.port &&
      e.method === entry.method &&
      e.path === entry.path
  )
  if (idx >= 0) {
    entries[idx] = { ...entries[idx], ...entry }
  } else {
    entries.push(entry)
  }
  writeSessionEgressEntries(entries, homeDir)
}

export function removeSessionEgressRule(
  criteria: { sandboxName?: string; workspacePath?: string; host: string; port?: number; method?: string; path?: string },
  homeDir = os.homedir()
): boolean {
  const entries = readSessionEgressEntries(homeDir)
  const normHost = criteria.host.toLowerCase()
  const filtered = entries.filter(e => {
    if (criteria.sandboxName !== undefined && (e.sandboxName || '') !== criteria.sandboxName) return true
    if (criteria.workspacePath && e.workspacePath !== criteria.workspacePath) return true
    if (e.host.toLowerCase() !== normHost) return true
    if (criteria.port !== undefined && e.port !== criteria.port) return true
    if (criteria.method && e.method !== criteria.method.toUpperCase()) return true
    if (criteria.path && e.path !== criteria.path) return true
    return false
  })
  if (filtered.length !== entries.length) {
    writeSessionEgressEntries(filtered, homeDir)
    return true
  }
  return false
}

export function pruneSandboxSessionEgress(sandboxName: string, homeDir = os.homedir()): void {
  if (!sandboxName) return
  const entries = readSessionEgressEntries(homeDir)
  const filtered = entries.filter(e => e.sandboxName !== sandboxName)
  if (filtered.length !== entries.length) {
    writeSessionEgressEntries(filtered, homeDir)
  }
}

export interface L7PolicySuggestion {
  ruleName: string
  host: string
  port: number
  action: 'allow' | 'deny'
  method: string
  path: string
  binary: string
  triggerCommand?: string
}

export interface CommandEvaluationResult {
  command: string
  verdict: 'allow' | 'deny' | 'ask'
  summary: string
  matchedRules: CliPermissionRule[]
  sandboxChecks: Array<{
    layer: string
    status: 'pass' | 'warn' | 'block'
    detail: string
  }>
  l7Suggestion?: L7PolicySuggestion
}

export interface AddL7PolicyRequest {
  scope: 'session' | 'workspace' | 'global'
  sandboxName?: string
  workspacePath?: string
  agent?: string
  ruleName?: string
  host: string
  port?: number
  action?: 'allow' | 'deny'
  method?: string
  path?: string
  binary?: string
  triggerCommand?: string
}

export interface AddL7PolicyResult {
  ok: boolean
  scope: 'session' | 'workspace' | 'global'
  message: string
  targetFile?: string
  appliedSandboxes?: string[]
  cliCommandsRun?: string[]
}

/** Format a canonical pattern like `git status:*` into a readable CLI command syntax. */
export function formatCliPattern(tool: string, pattern: string): { cliCommand: string; baseBinary: string } {
  if (tool !== 'Bash') {
    return {
      cliCommand: `${tool}(${pattern})`,
      baseBinary: tool.toLowerCase(),
    }
  }
  const trimmed = pattern.trim()
  const normalized = trimmed.endsWith(':*')
    ? `${trimmed.slice(0, -2)} [args...]`
    : trimmed.endsWith('*') && !trimmed.endsWith('/*')
      ? `${trimmed.slice(0, -1)}[args...]`
      : trimmed
  const firstToken = trimmed.replace(/:?\*$/, '').trim().split(/\s+/)[0] || trimmed
  return {
    cliCommand: normalized,
    baseBinary: firstToken,
  }
}

/** Parse YAML permission files (`name`, `description`, `allow`, `ask`, `deny`) without external deps. */
export function parsePermissionYaml(
  content: string,
  sourceFile: string,
  scope: 'global' | 'workspace'
): PermissionGroupSummary {
  let name = path.basename(sourceFile, path.extname(sourceFile))
  let description = ''
  let currentList: 'allow' | 'ask' | 'deny' | null = null
  const rules: CliPermissionRule[] = []

  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.replace(/#.*$/, '').trim()
    if (!line) continue

    const nameMatch = /^name:\s*(.+)$/.exec(line)
    if (nameMatch) {
      name = nameMatch[1].trim().replace(/^['"]|['"]$/g, '')
      currentList = null
      continue
    }
    const descMatch = /^description:\s*(.+)$/.exec(line)
    if (descMatch) {
      description = descMatch[1].trim().replace(/^['"]|['"]$/g, '')
      currentList = null
      continue
    }
    if (/^allow:\s*$/.test(line)) {
      currentList = 'allow'
      continue
    }
    if (/^ask:\s*$/.test(line)) {
      currentList = 'ask'
      continue
    }
    if (/^deny:\s*$/.test(line)) {
      currentList = 'deny'
      continue
    }

    if (currentList && line.startsWith('-')) {
      const item = line.slice(1).trim().replace(/^['"]|['"]$/g, '')
      const ruleMatch = /^(\w+)\((.*)\)$/.exec(item)
      const tool = ruleMatch ? ruleMatch[1] : 'Bash'
      const pattern = ruleMatch ? ruleMatch[2].trim() : item
      const { cliCommand, baseBinary } = formatCliPattern(tool, pattern)
      const groupDesc = description || `${scope === 'global' ? 'Global' : 'Workspace'} ${name} policy`
      const actionVerb =
        currentList === 'allow'
          ? 'Permits automatic execution without confirmation'
          : currentList === 'ask'
            ? 'Requires interactive user approval before execution'
            : 'Hard-blocks execution inside and outside the sandbox'
      const scopePath =
        scope === 'global'
          ? `~/.agents/permissions/${sourceFile}`
          : `.agents/permissions/${sourceFile}`
      rules.push({
        raw: item,
        tool,
        pattern,
        cliCommand,
        baseBinary,
        action: currentList,
        scope,
        groupName: name,
        groupDescription: groupDesc,
        sourceFile,
        explanation: `${actionVerb} for \`${cliCommand}\` under ${scope} policy "${name}" (${groupDesc}, defined in \`${scopePath}\`).`,
        compatibleAgents: ['claude', 'codex', 'antigravity'],
      })
    }
  }

  return {
    name,
    description: description || `${scope === 'global' ? 'Global' : 'Workspace'} ${name} policy`,
    scope,
    sourceFile,
    allowCount: rules.filter(r => r.action === 'allow').length,
    askCount: rules.filter(r => r.action === 'ask').length,
    denyCount: rules.filter(r => r.action === 'deny').length,
    rules,
  }
}

interface ParsedOpenShellPolicy {
  landlock?: string
  includeWorkdir?: boolean
  readOnly: string[]
  readWrite: string[]
  endpoints: NetworkEndpointRule[]
}

function compatibleCommandsForHost(host: string): string[] {
  if (host.includes('npmjs.org')) return ['npm view <pkg>', 'npm install --ignore-scripts', 'bun pm']
  if (host.includes('anthropic.com') || host.includes('statsig') || host.includes('sentry.io') || host.includes('datadoghq.com')) {
    return ['claude', 'claude-box']
  }
  if (host.includes('openai.com') || host.includes('chatgpt.com')) {
    return ['codex', 'codex-box']
  }
  if (host.includes('googleapis.com') || host.includes('google.com') || host.includes('googleusercontent.com')) {
    return ['agy', 'antigravity', 'agy-box']
  }
  if (host.includes('github.com') || host.includes('githubusercontent.com')) {
    return ['gh pr view', 'git fetch', 'git ls-remote', 'curl https://api.github.com/...']
  }
  if (host.includes('pypi.org') || host.includes('pythonhosted.org')) {
    return ['pip install <pkg>', 'uv pip install <pkg>']
  }
  if (host.includes('crates.io')) {
    return ['cargo add <crate>', 'cargo test']
  }
  return [`curl -sS https://${host}/...`, 'wget', 'fetch']
}

export function describeEndpointRelation(params: {
  host: string
  port: number
  policyName: string
  source: string
  binaries: string[]
  l7Rules?: L7HttpRule[]
  triggerCommand?: string
}): { triggerSource: string; triggerExplanation: string } {
  const { host, port, policyName, source, binaries, l7Rules, triggerCommand } = params
  const h = host.toLowerCase()

  if (triggerCommand && triggerCommand.trim()) {
    const cmd = triggerCommand.trim()
    const tokens = cmd.split(/\s+/)
    const shortCmd = tokens.slice(0, 2).join(' ')
    return {
      triggerSource: shortCmd.length <= 20 ? shortCmd : (tokens[0] || 'cli').slice(0, 20),
      triggerExplanation: `Triggered directly by CLI command/script \`${cmd}\` accessing https://${host}:${port} (defined in ${source}, policy \`${policyName}\`).`,
    }
  }

  if (h === 'api.anthropic.com') {
    return {
      triggerSource: 'claude',
      triggerExplanation: `Claude Code CLI (\`/usr/local/bin/claude\`) streams LLM inference turns, tool invocations, and token counting to \`https://${host}:${port}\` using supervisor-injected \`CLAUDE_CODE_OAUTH_TOKEN\` / \`ANTHROPIC_API_KEY\`.`,
    }
  }
  if (h.includes('statsig') || h.includes('sentry.io') || h.includes('datadoghq.com')) {
    return {
      triggerSource: 'claude sdk',
      triggerExplanation: `Claude Code startup and runtime SDK (\`/usr/local/bin/claude\`) queries \`${host}\` for feature-flag evaluation and crash diagnostics (${source}).`,
    }
  }
  if (h === 'api.openai.com' || h === 'chatgpt.com' || h === 'ab.chatgpt.com') {
    return {
      triggerSource: 'codex',
      triggerExplanation: `OpenAI Codex CLI (\`/usr/local/bin/codex app-server\`) connects to \`https://${host}:${port}\` for model responses, tool execution turns, and workspace turns (${source}).`,
    }
  }
  if (h === 'auth.openai.com') {
    return {
      triggerSource: 'codex auth',
      triggerExplanation: `Codex OAuth provider (\`codex-orca\`) refreshes short-lived session access tokens against \`https://${host}:${port}\` inside the OpenShell gateway.`,
    }
  }
  if (h.includes('cloudcode-pa.googleapis.com')) {
    return {
      triggerSource: 'agy',
      triggerExplanation: `Google Antigravity agent runtime (\`/usr/local/bin/agy\`) streams model completions and tool steps through \`https://${host}:${port}\` (${source}).`,
    }
  }
  if (h === 'oauth2.googleapis.com' || h === 'accounts.google.com') {
    return {
      triggerSource: 'agy auth',
      triggerExplanation: `Google Antigravity CLI exchanges and refreshes \`GOOGLE_OAUTH_*\` credentials against \`https://${host}:${port}\` (${source}).`,
    }
  }
  if (h === 'www.googleapis.com' || h === 'storage.googleapis.com' || h.includes('googleusercontent.com')) {
    return {
      triggerSource: 'agy cloud',
      triggerExplanation: `Google Antigravity CLI and SDK tools fetch workspace metadata and cloud storage resources from \`https://${host}:${port}\` (${source}).`,
    }
  }
  if (h.includes('npmjs.org')) {
    return {
      triggerSource: 'npm / bun',
      triggerExplanation: `Package manager commands (\`npm install\`, \`npm view\`, \`bun install\`, \`npx\`) fetch package tarballs and registry metadata from \`https://${host}:${port}\` (${source}).`,
    }
  }
  if (h === 'api.github.com' || h.includes('github.com') || h.includes('githubusercontent.com')) {
    const l7Desc = l7Rules?.length
      ? ` with L7 filter (${l7Rules.map(r => `${r.action.toUpperCase()} ${r.method} ${r.path}`).join(', ')})`
      : ''
    return {
      triggerSource: 'gh / git',
      triggerExplanation: `GitHub CLI (\`gh pr\`, \`gh issue\`, \`gh api\`), \`git fetch/push\`, or \`curl\` scripts calling \`https://${host}:${port}\`${l7Desc} (defined in ${source}).`,
    }
  }

  const shortBins = binaries
    .map(b => path.basename(b))
    .filter(Boolean)
    .slice(0, 2)
    .join(', ')
  const l7Note = l7Rules?.length
    ? ` Enforces L7 HTTP rules: ${l7Rules.map(r => `${r.action.toUpperCase()} ${r.method} ${r.path}`).join(', ')}.`
    : ''
  return {
    triggerSource: shortBins || 'curl / script',
    triggerExplanation: `Outbound requests from ${binaries.length ? `binaries \`${binaries.join(', ')}\`` : 'sandbox CLI commands or scripts'} to \`https://${host}:${port}\` via policy \`${policyName}\` (${source}).${l7Note}`,
  }
}

/** Parse either JSON or simple YAML OpenShell policy files. */
export function parseOpenShellPolicyFile(filePath: string): ParsedOpenShellPolicy {
  const result: ParsedOpenShellPolicy = {
    readOnly: [],
    readWrite: [],
    endpoints: [],
  }
  if (!fs.existsSync(filePath)) return result
  const content = fs.readFileSync(filePath, 'utf8')
  const sourceLabel = path.basename(filePath)

  if (filePath.endsWith('.json')) {
    try {
      const parsed = JSON.parse(content) as Record<string, any>
      if (parsed.landlock?.compatibility) result.landlock = String(parsed.landlock.compatibility)
      if (typeof parsed.filesystem_policy?.include_workdir === 'boolean') {
        result.includeWorkdir = parsed.filesystem_policy.include_workdir
      }
      if (Array.isArray(parsed.filesystem_policy?.read_only)) {
        result.readOnly.push(...parsed.filesystem_policy.read_only.map(String))
      }
      if (Array.isArray(parsed.filesystem_policy?.read_write)) {
        result.readWrite.push(...parsed.filesystem_policy.read_write.map(String))
      }
      if (parsed.network_policies && typeof parsed.network_policies === 'object') {
        for (const [policyKey, netPol] of Object.entries<any>(parsed.network_policies)) {
          const binaries = Array.isArray(netPol?.binaries)
            ? netPol.binaries.map((b: any) => typeof b === 'string' ? b : b?.path).filter(Boolean)
            : []
          for (const ep of netPol?.endpoints ?? []) {
            if (!ep?.host) continue
            const l7Rules: L7HttpRule[] = []
            for (const r of ep?.rules ?? []) {
              if (r?.allow?.method || r?.allow?.path) {
                l7Rules.push({
                  action: 'allow',
                  method: String(r.allow.method || '*'),
                  path: String(r.allow.path || '/**'),
                })
              }
            }
            for (const d of ep?.deny_rules ?? []) {
              if (d?.method || d?.path) {
                l7Rules.push({
                  action: 'deny',
                  method: String(d.method || '*'),
                  path: String(d.path || '/**'),
                })
              }
            }
            const hostStr = String(ep.host)
            const portNum = Number(ep.port || 443)
            const polName = netPol?.name || policyKey
            const rel = describeEndpointRelation({
              host: hostStr,
              port: portNum,
              policyName: polName,
              source: sourceLabel,
              binaries,
              l7Rules: l7Rules.length > 0 ? l7Rules : undefined,
              triggerCommand: ep?.trigger_command || netPol?.trigger_command,
            })
            result.endpoints.push({
              policyName: polName,
              source: sourceLabel,
              sourcePath: filePath,
              host: hostStr,
              port: portNum,
              protocol: String(ep.protocol || 'rest'),
              access: String(ep.access || (l7Rules.length > 0 ? 'l7-rules' : 'read-write')),
              enforcement: String(ep.enforcement || 'enforce'),
              binaries,
              compatibleCliCommands: compatibleCommandsForHost(hostStr),
              triggerSource: rel.triggerSource,
              triggerExplanation: rel.triggerExplanation,
              ...(l7Rules.length > 0 ? { l7Rules } : {}),
            })
          }
        }
      }
      return result
    } catch {
      return result
    }
  }

  // Lightweight YAML parser for OpenShell policy files
  let section: 'none' | 'fs_ro' | 'fs_rw' | 'net' = 'none'
  let currentNetPolicy = 'custom'
  let currentEndpoint: Partial<NetworkEndpointRule> | null = null

  const flushEndpoint = () => {
    if (currentEndpoint?.host) {
      const hostStr = currentEndpoint.host
      const portNum = currentEndpoint.port ?? 443
      const bins = currentEndpoint.binaries ?? []
      const rel = describeEndpointRelation({
        host: hostStr,
        port: portNum,
        policyName: currentNetPolicy,
        source: sourceLabel,
        binaries: bins,
      })
      result.endpoints.push({
        policyName: currentNetPolicy,
        source: sourceLabel,
        sourcePath: filePath,
        host: hostStr,
        port: portNum,
        protocol: currentEndpoint.protocol ?? 'rest',
        access: currentEndpoint.access ?? 'read-write',
        enforcement: currentEndpoint.enforcement ?? 'enforce',
        binaries: bins,
        compatibleCliCommands: compatibleCommandsForHost(hostStr),
        triggerSource: rel.triggerSource,
        triggerExplanation: rel.triggerExplanation,
      })
    }
    currentEndpoint = null
  }

  for (const rawLine of content.split(/\r?\n/)) {
    const trimmed = rawLine.replace(/#.*$/, '').trim()
    if (!trimmed) continue
    const indent = rawLine.search(/\S/)

    if (trimmed.startsWith('compatibility:')) {
      result.landlock = trimmed.split(':')[1]?.trim()
      continue
    }
    if (trimmed.startsWith('include_workdir:')) {
      result.includeWorkdir = trimmed.split(':')[1]?.trim() === 'true'
      continue
    }
    if (trimmed === 'read_only:') {
      flushEndpoint()
      section = 'fs_ro'
      continue
    }
    if (trimmed === 'read_write:') {
      flushEndpoint()
      section = 'fs_rw'
      continue
    }
    if (trimmed === 'network_policies:') {
      flushEndpoint()
      section = 'net'
      continue
    }
    if (trimmed === 'network_middlewares:' || trimmed === 'landlock:' || trimmed === 'filesystem_policy:') {
      flushEndpoint()
      if (trimmed !== 'filesystem_policy:') section = 'none'
      continue
    }

    if (section === 'fs_ro' && trimmed.startsWith('- ')) {
      result.readOnly.push(trimmed.slice(2).trim())
      continue
    }
    if (section === 'fs_rw' && trimmed.startsWith('- ')) {
      result.readWrite.push(trimmed.slice(2).trim())
      continue
    }
    if (section === 'net') {
      if (indent === 2 && trimmed.endsWith(':')) {
        flushEndpoint()
        currentNetPolicy = trimmed.slice(0, -1).trim()
        continue
      }
      if (trimmed.startsWith('- host:')) {
        flushEndpoint()
        currentEndpoint = { host: trimmed.slice('- host:'.length).trim() }
        continue
      }
      if (currentEndpoint) {
        if (trimmed.startsWith('port:')) currentEndpoint.port = Number(trimmed.slice('port:'.length).trim()) || 443
        else if (trimmed.startsWith('protocol:')) currentEndpoint.protocol = trimmed.slice('protocol:'.length).trim()
        else if (trimmed.startsWith('access:')) currentEndpoint.access = trimmed.slice('access:'.length).trim()
        else if (trimmed.startsWith('enforcement:')) currentEndpoint.enforcement = trimmed.slice('enforcement:'.length).trim()
      }
    }
  }
  flushEndpoint()
  return result
}

function normalizeAgentId(raw?: string | null): 'claude' | 'codex' | 'antigravity' | null {
  if (!raw) return null
  const lower = raw.toLowerCase().trim()
  if (lower === 'claude' || lower === 'claude-code' || lower === 'claude-box') return 'claude'
  if (lower === 'codex' || lower === 'codex-box') return 'codex'
  if (lower === 'antigravity' || lower === 'agy' || lower === 'agy-box' || lower === 'gemini') return 'antigravity'
  return null
}

export interface CurrentOrcaContext {
  workspace: WorkspaceEntry
  currentAgent: 'claude' | 'codex' | 'antigravity'
  activeAgentSessions: ActiveAgentSessionInfo[]
}

let cachedSandboxes: ActiveSandboxInfo[] = []
let lastSandboxRefreshAt = 0
let sandboxRefreshInFlight: Promise<void> | null = null

function resolveOrcaUserDataPath(homeDir = os.homedir()): string {
  if (process.env.ORCA_USER_DATA_PATH) return process.env.ORCA_USER_DATA_PATH
  if (process.platform === 'darwin') {
    return path.join(homeDir, 'Library', 'Application Support', 'orca')
  }
  return path.join(process.env.XDG_CONFIG_HOME || path.join(homeDir, '.config'), 'orca')
}

async function queryOrcaWorktreePsViaSocket(homeDir = os.homedir(), timeoutMs = 1200): Promise<OrcaWorktreePsEntry[] | null> {
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
  if (now - lastOrcaRefreshAt < 1500 && cachedOrcaWorktrees.length > 0) return

  orcaRefreshInFlight = (async () => {
    try {
      const worktrees = await queryOrcaWorktreePsViaSocket(homeDir, 1200)
      if (worktrees && worktrees.length > 0) {
        cachedOrcaWorktrees = worktrees
        lastOrcaRefreshAt = Date.now()
        syncOrcaWorktreeLineage(worktrees, homeDir)
      }
    } catch {} finally {
      orcaRefreshInFlight = null
    }
  })()
  return orcaRefreshInFlight
}

function inferSandboxAgent(name: string): string {
  if (name.startsWith('cc-')) return 'claude'
  if (name.startsWith('cx-')) return 'codex'
  if (name.startsWith('ag-')) return 'antigravity'
  return 'custom'
}

function parseSandboxListOutput(out: string): ActiveSandboxInfo[] {
  const trimmed = out.trim()
  if (trimmed.startsWith('{')) {
    try {
      const parsed = JSON.parse(trimmed) as {
        sandboxes?: Array<{ name?: string; created_at?: string; phase?: string }>
      }
      if (Array.isArray(parsed.sandboxes)) {
        return parsed.sandboxes
          .filter(s => typeof s?.name === 'string' && s.name.length > 0)
          .map(s => ({
            name: s.name!,
            created: typeof s.created_at === 'string' ? s.created_at : '',
            phase: typeof s.phase === 'string' && s.phase ? s.phase : 'Unknown',
            agent: inferSandboxAgent(s.name!),
          }))
      }
    } catch {}
  }

  const lines = out
    .split(/\r?\n/)
    .map(l => l.trim())
    .filter(l => l && !l.startsWith('NAME') && !l.startsWith('No sandboxes'))
  return lines.map(line => {
    const parts = line.split(/\s{2,}/)
    const name = parts[0] || line.split(/\s+/)[0] || ''
    const created = parts[1] || ''
    const phase = parts[2] || 'Unknown'
    return { name, created, phase, agent: inferSandboxAgent(name) }
  })
}

export async function refreshActiveSandboxesCache(force = false): Promise<void> {
  const now = Date.now()
  if (sandboxRefreshInFlight) return sandboxRefreshInFlight
  if (!force && now - lastSandboxRefreshAt < 2000) return

  sandboxRefreshInFlight = new Promise<void>((resolve) => {
    execFile('openshell', ['sandbox', 'list', '-o', 'json'], { timeout: 2500 }, (err, stdout) => {
      if (!err && typeof stdout === 'string') {
        cachedSandboxes = parseSandboxListOutput(stdout)
        lastSandboxRefreshAt = Date.now()
      }
      sandboxRefreshInFlight = null
      resolve()
    })
  })
  return sandboxRefreshInFlight
}

export async function pauseActiveSandbox(sandboxName: string): Promise<{ ok: boolean; message: string }> {
  const cleanName = String(sandboxName || '').trim()
  if (!/^[a-z0-9][a-z0-9-]{0,30}$/.test(cleanName)) {
    return { ok: false, message: `Invalid sandbox name "${sandboxName}".` }
  }
  return new Promise((resolve) => {
    execFile('openshell', ['sandbox', 'stop', cleanName], { timeout: 25000 }, async (err, _stdout, stderr) => {
      await refreshActiveSandboxesCache(true)
      if (err) {
        resolve({
          ok: false,
          message: String(stderr || err.message || `Failed to pause sandbox ${cleanName}`).trim(),
        })
        return
      }
      resolve({ ok: true, message: `Paused sandbox ${cleanName} (filesystem & policies preserved).` })
    })
  })
}

export async function resumeActiveSandbox(sandboxName: string): Promise<{ ok: boolean; message: string }> {
  const cleanName = String(sandboxName || '').trim()
  if (!/^[a-z0-9][a-z0-9-]{0,30}$/.test(cleanName)) {
    return { ok: false, message: `Invalid sandbox name "${sandboxName}".` }
  }
  return new Promise((resolve) => {
    execFile('openshell', ['sandbox', 'start', cleanName], { timeout: 35000 }, async (err, _stdout, stderr) => {
      await refreshActiveSandboxesCache(true)
      if (err) {
        resolve({
          ok: false,
          message: String(stderr || err.message || `Failed to resume sandbox ${cleanName}`).trim(),
        })
        return
      }
      resolve({ ok: true, message: `Resumed sandbox ${cleanName}.` })
    })
  })
}

export interface SandboxRegistryEntry {
  sandboxName: string
  agent: 'claude' | 'codex' | 'antigravity'
  workspacePath: string
  workspaceId?: string
  terminalId?: string
  agentSessionId?: string
  pid?: number
  createdAt?: string
  updatedAt?: string
}

export function getSandboxRegistryFilePath(homeDir = os.homedir()): string {
  if (process.env.ORCA_OPENSHELL_REGISTRY_FILE) {
    return process.env.ORCA_OPENSHELL_REGISTRY_FILE
  }
  return path.join(homeDir, '.config', 'orca-openshell', 'sandbox-registry.json')
}

function isHostPidAlive(pid?: number): boolean {
  if (pid === undefined || pid === null || pid <= 0) return true
  if (!Number.isFinite(pid) || pid <= 1) return false
  try {
    process.kill(pid, 0)
    return true
  } catch {
    return false
  }
}

export function pruneSandboxRegistryEntry(sandboxName: string, homeDir = os.homedir()): void {
  if (!sandboxName) return
  pruneSandboxIdleTimeout(sandboxName, homeDir)
  const regPath = getSandboxRegistryFilePath(homeDir)
  try {
    if (!fs.existsSync(regPath)) return
    const parsed = JSON.parse(fs.readFileSync(regPath, 'utf8')) as { entries?: SandboxRegistryEntry[] }
    if (!Array.isArray(parsed?.entries)) return
    const filtered = parsed.entries.filter(e => e?.sandboxName && e.sandboxName !== sandboxName)
    if (filtered.length !== parsed.entries.length) {
      fs.writeFileSync(regPath, JSON.stringify({ entries: filtered }, null, 2) + '\n', 'utf8')
    }
  } catch {}
}

function readSandboxRegistryMap(homeDir = os.homedir()): Map<string, SandboxRegistryEntry> {
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
      for (const rootDir of ['/tmp', '/private/tmp']) {
        if (!fs.existsSync(rootDir)) continue
        for (const agBase of fs.readdirSync(rootDir)) {
          if (!agBase.startsWith('orca-ag-openshell-')) continue
          const fullBase = path.join(rootDir, agBase)
          for (const sessKey of fs.readdirSync(fullBase)) {
            const stateFile = path.join(fullBase, sessKey, 'state.json')
            if (!fs.existsSync(stateFile)) continue
            try {
              const st = JSON.parse(fs.readFileSync(stateFile, 'utf8')) as {
                sandboxName?: string
                projectRoot?: string
                daemonPid?: number
              }
              if (st?.sandboxName && !map.has(st.sandboxName) && isHostPidAlive(st.daemonPid)) {
                map.set(st.sandboxName, {
                  sandboxName: st.sandboxName,
                  agent: 'antigravity',
                  workspacePath: st.projectRoot || '',
                  ...(sessKey.startsWith('antigravity_') ? { agentSessionId: sessKey } : {}),
                  pid: st.daemonPid,
                })
              }
            } catch {}
          }
        }
      }
    } catch {}
  }

  return map
}

export function extractAgentSessionIdFromPaneKey(paneKey?: string | null): string | null {
  if (!paneKey) return null
  const prefix = 'structured-agent-session-'
  if (paneKey.startsWith(prefix)) {
    const rest = paneKey.slice(prefix.length)
    const colonIdx = rest.indexOf(':')
    const id = colonIdx >= 0 ? rest.slice(0, colonIdx) : rest
    return id || null
  }
  return null
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

export async function stopActiveSandbox(sandboxName: string): Promise<{ ok: boolean; message: string }> {
  const cleanName = String(sandboxName || '').trim()
  if (!/^[a-z0-9][a-z0-9-]{0,30}$/.test(cleanName)) {
    return { ok: false, message: `Invalid sandbox name "${sandboxName}".` }
  }
  return new Promise((resolve) => {
    execFile('openshell', ['sandbox', 'delete', cleanName], { timeout: 10000 }, async (err, _stdout, stderr) => {
      pruneSandboxSessionEgress(cleanName)
      pruneSandboxRegistryEntry(cleanName)
      await refreshActiveSandboxesCache(true)
      if (err) {
        resolve({
          ok: false,
          message: String(stderr || err.message || `Failed to delete sandbox ${cleanName}`).trim(),
        })
        return
      }
      resolve({ ok: true, message: `Deleted sandbox ${cleanName}.` })
    })
  })
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

    const worktrees = cachedOrcaWorktrees
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

export function listActiveSandboxes(): ActiveSandboxInfo[] {
  void refreshActiveSandboxesCache()
  return cachedSandboxes
}

export function loadPermissionGroups(workspacePath: string, homeDir = os.homedir()): PermissionGroupSummary[] {
  const groups: PermissionGroupSummary[] = []
  const loadDir = (dir: string, scope: 'global' | 'workspace') => {
    if (!fs.existsSync(dir)) return
    const entries = fs.readdirSync(dir).filter(f => f.endsWith('.yml') || f.endsWith('.yaml')).sort()
    for (const file of entries) {
      const fullPath = path.join(dir, file)
      try {
        if (!fs.statSync(fullPath).isFile()) continue
        const content = fs.readFileSync(fullPath, 'utf8')
        groups.push(parsePermissionYaml(content, file, scope))
      } catch {}
    }
  }

  loadDir(path.join(homeDir, '.agents', 'permissions'), 'global')
  loadDir(path.join(workspacePath, '.agents', 'permissions'), 'workspace')
  return groups
}

export function inspectNativeSync(workspacePath: string): NativeAgentSyncStatus {
  const claudeSettingsPath = path.join(workspacePath, '.claude', 'settings.json')
  let claudeSynced = false
  let claudeAllowCount = 0
  let claudeDenyCount = 0
  if (fs.existsSync(claudeSettingsPath)) {
    try {
      const data = JSON.parse(fs.readFileSync(claudeSettingsPath, 'utf8'))
      claudeSynced = true
      claudeAllowCount = Array.isArray(data?.permissions?.allow) ? data.permissions.allow.length : 0
      claudeDenyCount = Array.isArray(data?.permissions?.deny) ? data.permissions.deny.length : 0
    } catch {}
  }

  const codexRulesPath = path.join(workspacePath, '.codex', 'rules', 'default.rules')
  let codexSynced = false
  let codexRuleCount = 0
  if (fs.existsSync(codexRulesPath)) {
    try {
      const content = fs.readFileSync(codexRulesPath, 'utf8')
      codexSynced = true
      codexRuleCount = (content.match(/prefix_rule\s*\(/g) || []).length
    } catch {}
  }

  const geminiSettingsPath = path.join(workspacePath, '.gemini', 'settings.json')
  let geminiSynced = false
  let geminiAllowCount = 0
  let geminiDenyCount = 0
  if (fs.existsSync(geminiSettingsPath)) {
    try {
      const data = JSON.parse(fs.readFileSync(geminiSettingsPath, 'utf8'))
      geminiSynced = true
      geminiAllowCount = Array.isArray(data?.tools?.allowed) ? data.tools.allowed.length : 0
      geminiDenyCount = Array.isArray(data?.tools?.exclude) ? data.tools.exclude.length : 0
    } catch {}
  }

  return {
    claudeSettingsPath,
    claudeSynced,
    claudeAllowCount,
    claudeDenyCount,
    codexRulesPath,
    codexSynced,
    codexRuleCount,
    geminiSettingsPath,
    geminiSynced,
    geminiAllowCount,
    geminiDenyCount,
  }
}

export async function buildPolicyReportAsync(options?: {
  workspacePath?: string
  agent?: string
  fallbackAgent?: string
  homeDir?: string
  binDir?: string
  orcaPolicyDir?: string
}): Promise<PolicyInspectionReport> {
  await Promise.all([
    refreshOrcaContextCache(options?.homeDir),
    refreshActiveSandboxesCache(),
  ])
  return buildPolicyReport(options)
}

export function buildPolicyReport(options?: {
  workspacePath?: string
  agent?: string
  fallbackAgent?: string
  homeDir?: string
  binDir?: string
  orcaPolicyDir?: string
}): PolicyInspectionReport {
  const homeDir = options?.homeDir || os.homedir()
  const binDir = options?.binDir || process.env.ORCA_OPENSHELL_BRIDGE_BIN_DIR || path.join(homeDir, '.local', 'bin')
  const orcaPolicyDir =
    options?.orcaPolicyDir ||
    process.env.ORCA_OPENSHELL_POLICY_DIR ||
    path.join(homeDir, '.agents', 'orca-openshell-policies')

  const context = discoverCurrentOrcaContext({
    workspacePath: options?.workspacePath,
    agent: options?.agent,
    fallbackAgent: options?.fallbackAgent,
    homeDir,
  })
  const selectedWorkspace = context.workspace
  const currentAgent = context.currentAgent

  const allSandboxesNow = listActiveSandboxes()
  const activeSandboxes = resolveCurrentTabSandbox({
    allSandboxes: allSandboxesNow,
    selectedWorkspace,
    currentAgent,
    activeAgentSessions: context.activeAgentSessions,
    homeDir,
  })
  const currentTabSandbox = activeSandboxes[0] || null

  const reqQueueDir = path.join(selectedWorkspace.path, '.orca-openshell-l7-requests')
  if (fs.existsSync(reqQueueDir)) {
    try {
      const files = fs.readdirSync(reqQueueDir).filter(f => f.endsWith('.json')).sort()
      for (const file of files) {
        const fullPath = path.join(reqQueueDir, file)
        try {
          const req = JSON.parse(fs.readFileSync(fullPath, 'utf8')) as Partial<AddL7PolicyRequest> & { sandbox?: string }
          fs.unlinkSync(fullPath)
          if (req.host) {
            addL7Policy(
              {
                scope: req.scope || 'session',
                sandboxName: req.sandboxName || req.sandbox || currentTabSandbox?.name,
                host: req.host,
                port: req.port,
                action: req.action || 'allow',
                method: req.method || 'GET',
                path: req.path || '/**',
                binary: req.binary || '*',
                workspacePath: selectedWorkspace.path,
                agent: currentAgent,
              },
              { homeDir, orcaPolicyDir }
            )
          }
        } catch {
          try { fs.unlinkSync(fullPath) } catch {}
        }
      }
      if (fs.readdirSync(reqQueueDir).length === 0) {
        try { fs.rmdirSync(reqQueueDir) } catch {}
      }
    } catch {}
  }

  const wsName = path.basename(selectedWorkspace.path)
  const globalDefaultPolicy = parseOpenShellPolicyFile(path.join(homeDir, '.agents', 'policies', 'default.yaml'))

  const projectPolicyDir = path.join(selectedWorkspace.path, '.agents', 'policies')
  const projectPolicies: ParsedOpenShellPolicy[] = []
  if (fs.existsSync(projectPolicyDir)) {
    try {
      for (const file of fs.readdirSync(projectPolicyDir).sort()) {
        if (file.endsWith('.yaml') || file.endsWith('.yml') || file.endsWith('.json')) {
          const parsed = parseOpenShellPolicyFile(path.join(projectPolicyDir, file))
          parsed.endpoints = parsed.endpoints.map(ep => ({
            ...ep,
            ruleScope: 'project' as const,
            temporary: false,
            sourcePath: `.agents/policies/${file}`,
          }))
          projectPolicies.push(parsed)
        }
      }
    } catch {}
  }

  const activeSandboxNames = new Set(allSandboxesNow.map(s => s.name))
  const rawSessionEntries = readSessionEgressEntries(homeDir)
  const validSessionEntries = rawSessionEntries.filter(entry => {
    if (!entry.sandboxName) return true
    if (activeSandboxNames.has(entry.sandboxName)) return true
    if (allSandboxesNow.length === 0) return true
    const ageMs = Date.now() - (Date.parse(entry.createdAt) || 0)
    return ageMs < 30000
  })
  if (validSessionEntries.length !== rawSessionEntries.length) {
    writeSessionEgressEntries(validSessionEntries, homeDir)
  }

  const buildAgentPolicy = (
    agent: 'claude' | 'codex' | 'antigravity',
    displayName: string,
    wrapperName: string,
    containerImage: string,
    providerProfile: string,
    credentialPlaceholders: string[],
    allowedBinaries: string[],
    profileEndpoints: Array<{ host: string; port?: number }>,
    surfaces: Array<{ surface: string; transport: string; cliExample: string }>
  ): AgentProfilePolicy => {
    const wrapperPath = path.join(binDir, wrapperName)
    const orcaPolicy = parseOpenShellPolicyFile(path.join(orcaPolicyDir, `${agent}.json`))
    const agentYamlPolicy = parseOpenShellPolicyFile(path.join(homeDir, '.agents', 'policies', `${agent}.yaml`))

    const readOnly = new Set<string>([
      ...orcaPolicy.readOnly,
      ...globalDefaultPolicy.readOnly,
      ...projectPolicies.flatMap(p => p.readOnly),
    ])
    const readWrite = new Set<string>([
      `/sandbox/${wsName}`,
      `/sandbox/${agent === 'claude' ? '.claude' : agent === 'codex' ? '.codex' : '.gemini'}`,
      ...orcaPolicy.readWrite,
      ...globalDefaultPolicy.readWrite,
      ...projectPolicies.flatMap(p => p.readWrite),
    ])

    const agentSessionEntries = validSessionEntries.filter(e => {
      if (currentTabSandbox) {
        return e.sandboxName === currentTabSandbox.name
      }
      return !e.sandboxName && e.workspacePath === selectedWorkspace.path && e.agent === agent
    })
    const sessionEndpointsByHost = new Map<string, NetworkEndpointRule>()
    for (const entry of agentSessionEntries) {
      const key = `${entry.host.toLowerCase()}:${entry.port}`
      const l7Rule: L7HttpRule = {
        action: entry.action,
        method: entry.method,
        path: entry.path,
      }
      const existing = sessionEndpointsByHost.get(key)
      if (existing) {
        existing.l7Rules = existing.l7Rules || []
        if (!existing.l7Rules.some(r => r.action === l7Rule.action && r.method === l7Rule.method && r.path === l7Rule.path)) {
          existing.l7Rules.push(l7Rule)
        }
      } else {
        const bins = entry.binary === '*'
          ? ['/usr/bin/curl', '/usr/bin/git', '/usr/local/bin/node', '/usr/bin/python3', '/usr/bin/gh']
          : [entry.binary]
        const rel = describeEndpointRelation({
          host: entry.host,
          port: entry.port,
          policyName: entry.ruleName,
          source: 'session-temporary',
          binaries: bins,
          l7Rules: [l7Rule],
          triggerCommand: entry.triggerCommand,
        })
        sessionEndpointsByHost.set(key, {
          policyName: entry.ruleName,
          source: entry.sandboxName ? `session (${entry.sandboxName})` : 'session-temporary',
          sourcePath: entry.sandboxName
            ? `Temporary rule on sandbox ${entry.sandboxName}`
            : 'Temporary rule (active session)',
          ruleScope: 'temporary',
          temporary: true,
          host: entry.host,
          port: entry.port,
          protocol: 'rest',
          access: 'l7-rules',
          enforcement: 'enforce',
          binaries: bins,
          compatibleCliCommands: compatibleCommandsForHost(entry.host),
          triggerSource: rel.triggerSource,
          triggerExplanation: rel.triggerExplanation,
          l7Rules: [l7Rule],
        })
      }
    }

    const endpoints: NetworkEndpointRule[] = [
      ...sessionEndpointsByHost.values(),
      ...projectPolicies.flatMap(p => p.endpoints),
      ...orcaPolicy.endpoints.map(ep => ({ ...ep, ruleScope: 'global' as const, temporary: false })),
      ...agentYamlPolicy.endpoints.map(ep => ({ ...ep, ruleScope: 'global' as const, temporary: false })),
      ...globalDefaultPolicy.endpoints.map(ep => ({ ...ep, ruleScope: 'global' as const, temporary: false })),
      ...profileEndpoints.map(ep => {
        const portNum = ep.port ?? 443
        const polName = `provider:${providerProfile}`
        const srcName = `${providerProfile}.profile.yaml`
        const rel = describeEndpointRelation({
          host: ep.host,
          port: portNum,
          policyName: polName,
          source: srcName,
          binaries: allowedBinaries,
        })
        return {
          policyName: polName,
          source: srcName,
          sourcePath: `profiles/${srcName}`,
          ruleScope: 'profile' as const,
          temporary: false,
          host: ep.host,
          port: portNum,
          protocol: 'rest',
          access: 'read-write',
          enforcement: 'enforce',
          binaries: allowedBinaries,
          compatibleCliCommands: compatibleCommandsForHost(ep.host),
          triggerSource: rel.triggerSource,
          triggerExplanation: rel.triggerExplanation,
        }
      }),
    ]

    const mergedByKey = new Map<string, NetworkEndpointRule>()
    for (const ep of endpoints) {
      const key = `${ep.host.toLowerCase()}:${ep.port}`
      const existing = mergedByKey.get(key)
      if (!existing) {
        const clone: NetworkEndpointRule = { ...ep }
        if (ep.l7Rules) {
          clone.l7Rules = [...ep.l7Rules]
        } else {
          delete clone.l7Rules
        }
        mergedByKey.set(key, clone)
        continue
      }
      if (ep.l7Rules && ep.l7Rules.length > 0) {
        existing.l7Rules = existing.l7Rules ? [...existing.l7Rules] : []
        for (const r of ep.l7Rules) {
          if (!existing.l7Rules.some(er => er.action === r.action && er.method === r.method && er.path === r.path)) {
            existing.l7Rules.push(r)
          }
        }
      }
    }
    const dedupedEndpoints = [...mergedByKey.values()]

    return {
      agent,
      displayName,
      hostWrapper: wrapperPath,
      hostWrapperInstalled: fs.existsSync(wrapperPath),
      containerImage,
      providerProfile,
      surfaces,
      credentialPlaceholders,
      allowedBinaries,
      landlockMode: orcaPolicy.landlock || 'hard_requirement',
      filesystemReadWrite: [...readWrite],
      filesystemReadOnly: [...readOnly],
      endpoints: dedupedEndpoints,
    }
  }

  const allAgents: AgentProfilePolicy[] = [
    buildAgentPolicy(
      'claude',
      'Claude Code',
      'claude-box',
      'openshell-claude:latest',
      'claude-code',
      ['CLAUDE_CODE_OAUTH_TOKEN', 'ANTHROPIC_API_KEY'],
      ['/usr/local/bin/claude', '/usr/local/bin/node', '/usr/bin/node'],
      [
        { host: 'api.anthropic.com' },
        { host: 'statsig.anthropic.com' },
        { host: 'statsigapi.net' },
        { host: 'sentry.io' },
        { host: 'http-intake.logs.us5.datadoghq.com' },
      ],
      [
        {
          surface: 'Chat Mode (Structured)',
          transport: 'SSH full-duplex stream-json (--no-tty)',
          cliExample: 'orca agent launch --agent claude --surface chat --prompt "..."',
        },
        {
          surface: 'Terminal Mode (Interactive TUI)',
          transport: 'OpenShell gRPC exec (--tty)',
          cliExample: 'orca agent launch --agent claude --surface terminal',
        },
        {
          surface: 'Standalone CLI',
          transport: 'Direct wrapper invocation',
          cliExample: 'claude-box -p "Inspect repository"',
        },
      ]
    ),
    buildAgentPolicy(
      'codex',
      'OpenAI Codex',
      'codex-box',
      'openshell-codex:latest',
      'codex-orca',
      ['CODEX_AUTH_ACCESS_TOKEN', 'CODEX_AUTH_ACCOUNT_ID', 'OPENAI_API_KEY'],
      ['/usr/local/bin/codex', '/usr/local/bin/node', '/usr/bin/node'],
      [
        { host: 'api.openai.com' },
        { host: 'auth.openai.com' },
        { host: 'chatgpt.com' },
        { host: 'ab.chatgpt.com' },
      ],
      [
        {
          surface: 'Chat Mode (Structured)',
          transport: 'SSH full-duplex JSON-RPC app-server (--no-tty)',
          cliExample: 'orca agent launch --agent codex --surface chat --prompt "..."',
        },
        {
          surface: 'Terminal Mode (Interactive TUI)',
          transport: 'OpenShell gRPC exec (--tty)',
          cliExample: 'orca agent launch --agent codex --surface terminal',
        },
        {
          surface: 'Standalone CLI',
          transport: 'Direct wrapper invocation',
          cliExample: 'codex-box "Fix failing tests"',
        },
      ]
    ),
    buildAgentPolicy(
      'antigravity',
      'Google Antigravity',
      'agy-box',
      'openshell-antigravity:latest',
      'antigravity',
      ['GOOGLE_OAUTH_ACCESS_TOKEN', 'GOOGLE_OAUTH_REFRESH_TOKEN', 'GOOGLE_OAUTH_ID_TOKEN'],
      ['/usr/local/bin/agy', '/usr/local/bin/antigravity', '/usr/bin/agy'],
      [
        { host: 'daily-cloudcode-pa.googleapis.com' },
        { host: 'cloudcode-pa.googleapis.com' },
        { host: 'www.googleapis.com' },
        { host: 'oauth2.googleapis.com' },
        { host: 'accounts.google.com' },
        { host: 'storage.googleapis.com' },
      ],
      [
        {
          surface: 'Terminal Mode (Interactive TUI)',
          transport: 'OpenShell gRPC exec (--tty)',
          cliExample: 'orca agent launch --agent antigravity --surface terminal',
        },
        {
          surface: 'Standalone CLI',
          transport: 'Direct wrapper invocation',
          cliExample: 'agy-box --prompt "Explain Landlock policy"',
        },
      ]
    ),
  ]

  // Only show the currently running agent's profile policy
  const agents = allAgents.filter(a => a.agent === currentAgent)

  const permissionGroups = loadPermissionGroups(selectedWorkspace.path, homeDir)
  const allCliRules = permissionGroups.flatMap(g => g.rules)

  // Delegation configuration & active grants for the current workspace
  const delegationConfigPath = path.join(selectedWorkspace.path, '.agents', 'delegation.json')
  let autoGrantEnabled = process.env.ORCA_AUTO_GRANT_DELEGATION === '1'
  let allowedAgents = ['claude', 'antigravity', 'codex']
  let maxWorkers = 2
  let maxDepth = 1
  if (fs.existsSync(delegationConfigPath)) {
    try {
      const cfg = JSON.parse(fs.readFileSync(delegationConfigPath, 'utf8'))
      if (typeof cfg.autoGrant === 'boolean') autoGrantEnabled = cfg.autoGrant
      if (Array.isArray(cfg.agents)) allowedAgents = cfg.agents.map(String)
      if (typeof cfg.maxWorkers === 'number') maxWorkers = cfg.maxWorkers
      if (typeof cfg.maxDepth === 'number') maxDepth = cfg.maxDepth
    } catch {}
  }

  const activeGrants: DelegationPolicySummary['activeGrants'] = []
  const grantsDir = path.join(homeDir, '.agents', 'orca-openshell-delegation', 'grants')
  if (fs.existsSync(grantsDir)) {
    try {
      for (const file of fs.readdirSync(grantsDir)) {
        if (!file.endsWith('.json')) continue
        const data = JSON.parse(fs.readFileSync(path.join(grantsDir, file), 'utf8'))
        const ws = String(data.workspaceId || '')
        if (ws && !ws.includes(selectedWorkspace.path) && ws !== selectedWorkspace.id) continue
        activeGrants.push({
          terminal: String(data.terminalId || file.replace(/\.json$/, '')),
          workspace: ws,
          agents: Array.isArray(data.allowedAgents) ? data.allowedAgents.map(String) : [],
          depth: Number(data.depth ?? 0),
          maxDepth: Number(data.maxDepth ?? 1),
          maxWorkers: Number(data.maxWorkers ?? 0),
          remainingWorkers: Number(data.remainingWorkers ?? 0),
        })
      }
    } catch {}
  }

  const delegation: DelegationPolicySummary = {
    autoGrantEnabled,
    configPath: fs.existsSync(delegationConfigPath) ? delegationConfigPath : null,
    allowedAgents,
    maxWorkers,
    maxDepth,
    activeGrants,
    allowedCliCommands: [
      {
        command: `orca orchestration worker-start --agent ${currentAgent} --spec "<task>" --worktree current --json`,
        description: 'Spawns a supervised worker in its own isolated OpenShell sandbox (depth + 1)',
      },
      {
        command: 'orca orchestration worker-show --dispatch <dispatch-id> --json',
        description: 'Inspects worker dispatch state and metadata via the host FIFO broker',
      },
      {
        command: 'orca orchestration worker-read --dispatch <dispatch-id> --json',
        description: 'Reads bounded output from a supervised worker sandbox',
      },
      {
        command: 'orca orchestration check [--peek] [--wait <sec>] --json',
        description: 'Checks coordinator/worker orchestration inbox messages',
      },
      {
        command: 'orca orchestration send --to <recipient> --type <type> --body "<msg>" --json',
        description: 'Sends an orchestration message with broker-enforced --from identity',
      },
      {
        command: 'orca orchestration reply --message <msg-id> --body "<reply>" --json',
        description: 'Replies to an orchestration message with broker-enforced --from identity',
      },
    ],
    blockedFlags: ['--environment', '--from', '--server-url', '--token', '--terminal (for worker-start)'],
  }

  const activeSession = context.activeAgentSessions[0] || null
  const sandboxIdleTimeoutSeconds = getSandboxIdleTimeoutSeconds(
    {
      sandboxName: currentTabSandbox?.name,
      paneKey: activeSession?.paneKey,
      workspacePath: selectedWorkspace.path,
      agent: currentAgent,
    },
    homeDir
  )

  const orcaBrokerRules: CliPermissionRule[] = [
    ...delegation.allowedCliCommands.map(c => {
      const subVerb = c.command.split(/\s+/)[2] || 'orchestration'
      return {
        raw: `Bash(orca orchestration ${subVerb}:*)`,
        tool: 'Bash',
        pattern: `orca orchestration ${subVerb}:*`,
        cliCommand: c.command,
        baseBinary: 'orca',
        action: 'allow' as const,
        scope: (delegation.configPath ? 'workspace' : 'global') as 'workspace' | 'global',
        groupName: 'delegation-broker',
        groupDescription: 'OpenShell FIFO Delegation Broker shim (/sandbox/.orca-delegate/bin/orca)',
        sourceFile: delegation.configPath ? 'delegation.json' : 'orca-delegation-shim.js',
        explanation: `${c.description}. Allowed over the restricted OpenShell exec FIFO channel (${delegation.autoGrantEnabled ? 'Auto-Grant enabled' : 'Manual grant'}, maxWorkers: ${delegation.maxWorkers}, maxDepth: ${delegation.maxDepth}).`,
        compatibleAgents: ['claude', 'codex', 'antigravity'],
      }
    }),
    {
      raw: 'Bash(orca orchestration * --token|--server-url|--from|--environment)',
      tool: 'Bash',
      pattern: 'orca orchestration * --from:*',
      cliCommand: 'orca orchestration [subcmd] --from | --token | --server-url | --environment',
      baseBinary: 'orca',
      action: 'deny' as const,
      scope: 'global' as const,
      groupName: 'delegation-broker',
      groupDescription: 'OpenShell FIFO Delegation Broker shim (/sandbox/.orca-delegate/bin/orca)',
      sourceFile: 'orca-delegation-shim.js',
      explanation: `Hard-blocks privileged identity spoofing and remote placement override flags (${delegation.blockedFlags.join(', ')}) inside the sandbox.`,
      compatibleAgents: ['claude', 'codex', 'antigravity'],
    },
  ]

  const combinedCliRules = [...allCliRules, ...orcaBrokerRules]
  const sandboxMode = getSandboxMode(
    { workspacePath: selectedWorkspace.path, workspaceId: selectedWorkspace.id },
    homeDir
  )

  return {
    generatedAt: new Date().toISOString(),
    sandboxEnabled: sandboxMode.enabled,
    sandboxInheritedFrom: sandboxMode.inheritedFrom,
    sandboxIdleTimeoutSeconds,
    selectedWorkspace,
    currentAgent,
    activeAgentSessions: context.activeAgentSessions,
    workspaces: [selectedWorkspace],
    activeSandboxes,
    agents,
    permissionGroups,
    allCliRules: combinedCliRules,
    delegation,
    nativeSync: inspectNativeSync(selectedWorkspace.path),
  }
}

function matchesBashRule(command: string, pattern: string): boolean {
  const normCmd = command.trim()
  const normPat = pattern.trim()
  if (normPat.endsWith(':*')) {
    const prefix = normPat.slice(0, -2).trim()
    return normCmd === prefix || normCmd.startsWith(`${prefix} `)
  }
  if (normPat.endsWith('*')) {
    const prefix = normPat.slice(0, -1)
    return normCmd.startsWith(prefix)
  }
  return normCmd === normPat
}

/** Evaluate a CLI command against both canonical CLI permissions and OpenShell sandbox layers. */
export function evaluateCommandPolicy(command: string, report: PolicyInspectionReport): CommandEvaluationResult {
  const trimmed = command.trim()
  const matchedRules = report.allCliRules.filter(
    rule => rule.tool === 'Bash' && matchesBashRule(trimmed, rule.pattern)
  )

  const denies = matchedRules.filter(r => r.action === 'deny')
  const asks = matchedRules.filter(r => r.action === 'ask')
  const allows = matchedRules.filter(r => r.action === 'allow')

  let verdict: 'allow' | 'deny' | 'ask' = 'ask'
  let summary = 'Unlisted command — requires interactive confirmation (or allowed inside disposable sandbox).'

  const sandboxChecks: CommandEvaluationResult['sandboxChecks'] = []
  if (report.sandboxEnabled === false) {
    sandboxChecks.push({
      layer: 'OpenShell Sandbox',
      status: 'warn',
      detail: 'Deactivated (Host Mode) - command runs unsandboxed on host without Landlock or L7 isolation.',
    })
  }

  // Check if it is an `orca orchestration` shim command
  if (trimmed.startsWith('orca ')) {
    const allowedSub = /^orca\s+orchestration\s+(worker-start|worker-show|worker-read|check|send|reply)\b/.exec(trimmed)
    const hasBlockedFlag = ['--environment', '--from', '--server-url', '--token'].some(f => trimmed.includes(f))
    if (allowedSub && !hasBlockedFlag) {
      verdict = 'allow'
      summary = `Permitted by OpenShell FIFO Delegation Broker (${allowedSub[1]}).`
      sandboxChecks.push({
        layer: 'Delegation Broker Shim (/sandbox/.orca-delegate/bin/orca)',
        status: 'pass',
        detail: `Subcommand '${allowedSub[1]}' is whitelisted over the OpenShell exec FIFO channel.`,
      })
    } else {
      verdict = 'deny'
      summary = hasBlockedFlag
        ? 'Blocked by OpenShell Delegation Broker: privileged identity/placement override flags are refused.'
        : 'Blocked by OpenShell Delegation Broker: only bounded orchestration verbs (worker-start, worker-show, worker-read, check, send, reply) are permitted inside the sandbox.'
      sandboxChecks.push({
        layer: 'Delegation Broker Shim (/sandbox/.orca-delegate/bin/orca)',
        status: 'block',
        detail: summary,
      })
    }
  } else if (denies.length > 0) {
    verdict = 'deny'
    summary = `Hard-blocked by ${denies[0].scope} policy '${denies[0].groupName}' (${denies[0].raw}).`
  } else if (asks.length > 0) {
    verdict = 'ask'
    summary = `Prompts for confirmation per ${asks[0].scope} policy '${asks[0].groupName}' (${asks[0].raw}).`
  } else if (allows.length > 0) {
    verdict = 'allow'
    summary = `Explicitly allowed by ${allows[0].scope} policy '${allows[0].groupName}' (${allows[0].raw}).`
  }

  // Landlock filesystem check
  const sampleAgent = report.agents[0]
  if (sampleAgent) {
    const writesSystemPath = /(?:^|\s)(?:\/etc|\/bin|\/usr|\/lib|\/System|\/Users)(?:\/|\s|$)/.test(trimmed) &&
      /\b(?:rm|mv|cp|touch|chmod|chown|tee|dd|mkfs)\b|>/.test(trimmed)
    if (writesSystemPath) {
      sandboxChecks.push({
        layer: `Landlock Filesystem (${sampleAgent.landlockMode})`,
        status: 'block',
        detail: 'Kernel Landlock policy blocks writes outside /sandbox/<workspace> and /tmp.',
      })
      verdict = 'deny'
    } else {
      sandboxChecks.push({
        layer: `Landlock Filesystem (${sampleAgent.landlockMode})`,
        status: 'pass',
        detail: `Read-Write in /sandbox/${report.selectedWorkspace.name} & /tmp; Read-Only in ${sampleAgent.filesystemReadOnly.join(', ')}.`,
      })
    }
  }

  // Network egress & L7 check if a URL or network CLI tool is referenced
  let l7Suggestion: L7PolicySuggestion | undefined
  const urlMatch = /https?:\/\/([^/\s:]+)(?::(\d+))?(\/[^\s"']*)?/.exec(trimmed)
  const firstBin = trimmed.split(/\s+/)[0] || 'curl'
  const inferredBinary = firstBin.startsWith('/') ? firstBin : `/usr/bin/${firstBin}`

  if (urlMatch) {
    const host = urlMatch[1].toLowerCase()
    const port = urlMatch[2] ? Number(urlMatch[2]) : 443
    const rawPath = urlMatch[3] || '/**'
    const methodMatch = /(?:-X|--request)\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)/i.exec(trimmed)
    const method = methodMatch ? methodMatch[1].toUpperCase() : 'GET'
    const ruleName = `${host.replace(/[^a-z0-9]+/g, '_')}_l7`

    l7Suggestion = {
      ruleName,
      host,
      port,
      action: 'allow',
      method,
      path: rawPath.endsWith('*') ? rawPath : `${rawPath.replace(/\/$/, '') || ''}/**`,
      binary: '*',
      triggerCommand: trimmed,
    }

    const allEndpoints = report.agents.flatMap(a => a.endpoints)
    const matchedEp = allEndpoints.find(ep => ep.host.toLowerCase() === host)
    if (matchedEp) {
      const l7Summary = matchedEp.l7Rules?.length
        ? ` [L7 rules: ${matchedEp.l7Rules.map(r => `${r.action.toUpperCase()} ${r.method} ${r.path}`).join(', ')}]`
        : ''
      sandboxChecks.push({
        layer: 'OpenShell mTLS & L7 Egress Proxy',
        status: 'pass',
        detail: `Host '${host}:${matchedEp.port}' is allowed (${matchedEp.access}) via ${matchedEp.policyName}${l7Summary}.`,
      })
    } else {
      sandboxChecks.push({
        layer: 'OpenShell mTLS & L7 Egress Proxy',
        status: 'block',
        detail: `Host '${host}:${port}' is not in any allowed network_policies endpoint list; egress will be denied unless an L7 policy is added.`,
      })
    }
  } else if (/^gh\s+/.test(trimmed)) {
    l7Suggestion = {
      ruleName: 'github_l7',
      host: 'api.github.com',
      port: 443,
      action: 'allow',
      method: /gh\s+(?:pr|issue)\s+(?:create|edit|comment|merge|close)/i.test(trimmed) ? 'POST' : 'GET',
      path: '/repos/**',
      binary: '/usr/bin/gh',
      triggerCommand: trimmed,
    }
  } else if (/^(?:npm|npx|bun)\s+/.test(trimmed)) {
    l7Suggestion = {
      ruleName: 'npm_registry_l7',
      host: 'registry.npmjs.org',
      port: 443,
      action: 'allow',
      method: 'GET',
      path: '/**',
      binary: '*',
      triggerCommand: trimmed,
    }
  }

  return {
    command: trimmed,
    verdict,
    summary,
    matchedRules,
    sandboxChecks,
    ...(l7Suggestion ? { l7Suggestion } : {}),
  }
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
  const effectiveBinaries =
    binary === '*'
      ? ['/usr/bin/curl', '/usr/bin/git', '/usr/local/bin/node', '/usr/bin/python3', '/usr/bin/gh']
      : [binary]
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
    if (req.scope === 'workspace') {
      const policyDir = path.join(wsPath, '.agents', 'policies')
      fs.mkdirSync(policyDir, { recursive: true })
      targetFile = path.join(policyDir, 'l7-custom.json')
    } else {
      fs.mkdirSync(orcaPolicyDir, { recursive: true })
      targetFile = path.join(orcaPolicyDir, `${resolvedAgent}.json`)
    }

    let doc: Record<string, any> = {
      version: 1,
      network_policies: {},
    }
    if (fs.existsSync(targetFile)) {
      try {
        doc = JSON.parse(fs.readFileSync(targetFile, 'utf8'))
      } catch {}
    }
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
    if (req.triggerCommand && req.triggerCommand.trim()) {
      ep.trigger_command = req.triggerCommand.trim()
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
    fs.writeFileSync(targetFile, JSON.stringify(doc, null, 2) + '\n', 'utf8')

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
      execFileSync('openshell', step1Args, {
        encoding: 'utf8',
        timeout: 8000,
        stdio: ['ignore', 'pipe', 'pipe'],
      })
      execFileSync('openshell', step2Args, {
        encoding: 'utf8',
        timeout: 8000,
        stdio: ['ignore', 'pipe', 'pipe'],
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
