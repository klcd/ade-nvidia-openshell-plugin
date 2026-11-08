import { execFileSync } from 'node:child_process'
import fs from 'node:fs'
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
  sourceFile: string
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

export interface NetworkEndpointRule {
  policyName: string
  source: string
  host: string
  port: number
  protocol: string
  access: string
  enforcement: string
  binaries: string[]
  compatibleCliCommands: string[]
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

export interface PolicyInspectionReport {
  generatedAt: string
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
      rules.push({
        raw: item,
        tool,
        pattern,
        cliCommand,
        baseBinary,
        action: currentList,
        scope,
        groupName: name,
        sourceFile,
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
    return ['gh pr view', 'git fetch', 'git ls-remote']
  }
  return ['curl', 'fetch']
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
            result.endpoints.push({
              policyName: netPol?.name || policyKey,
              source: sourceLabel,
              host: String(ep.host),
              port: Number(ep.port || 443),
              protocol: String(ep.protocol || 'rest'),
              access: String(ep.access || 'read-write'),
              enforcement: String(ep.enforcement || 'enforce'),
              binaries,
              compatibleCliCommands: compatibleCommandsForHost(String(ep.host)),
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
      result.endpoints.push({
        policyName: currentNetPolicy,
        source: sourceLabel,
        host: currentEndpoint.host,
        port: currentEndpoint.port ?? 443,
        protocol: currentEndpoint.protocol ?? 'rest',
        access: currentEndpoint.access ?? 'read-write',
        enforcement: currentEndpoint.enforcement ?? 'enforce',
        binaries: currentEndpoint.binaries ?? [],
        compatibleCliCommands: compatibleCommandsForHost(currentEndpoint.host),
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

/**
 * Queries Orca for the currently active worktree (`orca worktree current --json` + `orca worktree ps --json`)
 * and detects the currently running/active agent in that worktree.
 */
export function discoverCurrentOrcaContext(options?: {
  workspacePath?: string
  agent?: string
}): CurrentOrcaContext {
  let activeWorkspace: WorkspaceEntry | null = null
  const activeAgentSessions: ActiveAgentSessionInfo[] = []
  let detectedAgent: 'claude' | 'codex' | 'antigravity' | null = normalizeAgentId(options?.agent)

  // If an explicit workspacePath is passed (e.g. unit tests), honour it directly without slow CLI calls if it's a temp dir
  const isExplicitTestPath =
    Boolean(options?.workspacePath) &&
    (options!.workspacePath!.includes('openshell-policy-test-') || !fs.existsSync(path.join(options!.workspacePath!, '.git')))

  if (!isExplicitTestPath) {
    // 1. Check `orca worktree current --json` for the exact focused project in Orca UI
    try {
      const currentOut = execFileSync('orca', ['worktree', 'current', '--json'], {
        encoding: 'utf8',
        timeout: 2500,
        stdio: ['ignore', 'pipe', 'ignore'],
      })
      const parsed = JSON.parse(currentOut) as {
        result?: {
          worktree?: {
            id?: string
            path?: string
            displayName?: string
            branch?: string | null
          }
        }
      }
      const wt = parsed.result?.worktree
      if (wt?.path && (!options?.workspacePath || wt.path === options.workspacePath)) {
        activeWorkspace = {
          id: wt.id || `local::${wt.path}`,
          name: wt.displayName || path.basename(wt.path),
          path: wt.path,
          branch: wt.branch ? wt.branch.replace(/^refs\/heads\//, '') : null,
        }
      }
    } catch {}

    // 2. Check `orca worktree ps --limit 15 --json` to find active agent sessions in the current worktree
    try {
      const psOut = execFileSync('orca', ['worktree', 'ps', '--limit', '15', '--json'], {
        encoding: 'utf8',
        timeout: 2500,
        stdio: ['ignore', 'pipe', 'ignore'],
      })
      const parsed = JSON.parse(psOut) as {
        result?: {
          worktrees?: Array<{
            worktreeId?: string
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
          }>
        }
      }
      const worktrees = parsed.result?.worktrees ?? []
      const targetWt =
        (options?.workspacePath ? worktrees.find(w => w.path === options.workspacePath) : undefined) ||
        (activeWorkspace ? worktrees.find(w => w.path === activeWorkspace!.path) : undefined) ||
        worktrees.find(w => w.isActive) ||
        worktrees[0]

      if (targetWt?.path) {
        if (!activeWorkspace) {
          activeWorkspace = {
            id: targetWt.worktreeId || `local::${targetWt.path}`,
            name: targetWt.repo || targetWt.displayName || path.basename(targetWt.path),
            path: targetWt.path,
            branch: targetWt.branch ? targetWt.branch.replace(/^refs\/heads\//, '') : null,
          }
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
    } catch {}
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

  // Also check running OpenShell sandboxes if no agent session was found via worktree ps
  if (!detectedAgent) {
    const sandboxes = listActiveSandboxes()
    const sbAgent = sandboxes.map(s => normalizeAgentId(s.agent)).find(Boolean)
    if (sbAgent) detectedAgent = sbAgent
  }

  return {
    workspace: activeWorkspace,
    currentAgent: detectedAgent || 'claude',
    activeAgentSessions,
  }
}

export function listActiveSandboxes(): ActiveSandboxInfo[] {
  try {
    const out = execFileSync('openshell', ['sandbox', 'list'], {
      encoding: 'utf8',
      timeout: 3000,
      stdio: ['ignore', 'pipe', 'ignore'],
    })
    const lines = out
      .split(/\r?\n/)
      .map(l => l.trim())
      .filter(l => l && !l.startsWith('NAME') && !l.startsWith('No sandboxes'))
    return lines.map(line => {
      const parts = line.split(/\s{2,}/)
      const name = parts[0] || line.split(/\s+/)[0] || ''
      const created = parts[1] || ''
      const phase = parts[2] || 'Unknown'
      const agent = name.startsWith('cc-')
        ? 'claude'
        : name.startsWith('cx-')
          ? 'codex'
          : name.startsWith('ag-')
            ? 'antigravity'
            : 'custom'
      return { name, created, phase, agent }
    })
  } catch {
    return []
  }
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

export function buildPolicyReport(options?: {
  workspacePath?: string
  agent?: string
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
  })
  const selectedWorkspace = context.workspace
  const currentAgent = context.currentAgent

  const wsName = path.basename(selectedWorkspace.path)
  const globalDefaultPolicy = parseOpenShellPolicyFile(path.join(homeDir, '.agents', 'policies', 'default.yaml'))

  const projectPolicyDir = path.join(selectedWorkspace.path, '.agents', 'policies')
  const projectPolicies: ParsedOpenShellPolicy[] = []
  if (fs.existsSync(projectPolicyDir)) {
    try {
      for (const file of fs.readdirSync(projectPolicyDir).sort()) {
        if (file.endsWith('.yaml') || file.endsWith('.yml') || file.endsWith('.json')) {
          projectPolicies.push(parseOpenShellPolicyFile(path.join(projectPolicyDir, file)))
        }
      }
    } catch {}
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

    const endpoints: NetworkEndpointRule[] = [
      ...profileEndpoints.map(ep => ({
        policyName: `provider:${providerProfile}`,
        source: `${providerProfile}.profile.yaml`,
        host: ep.host,
        port: ep.port ?? 443,
        protocol: 'rest',
        access: 'read-write',
        enforcement: 'enforce',
        binaries: allowedBinaries,
        compatibleCliCommands: compatibleCommandsForHost(ep.host),
      })),
      ...globalDefaultPolicy.endpoints,
      ...agentYamlPolicy.endpoints,
      ...orcaPolicy.endpoints,
      ...projectPolicies.flatMap(p => p.endpoints),
    ]

    const seenEndpoints = new Set<string>()
    const dedupedEndpoints = endpoints.filter(ep => {
      const key = `${ep.host}:${ep.port}`
      if (seenEndpoints.has(key)) return false
      seenEndpoints.add(key)
      return true
    })

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

  const allSandboxes = listActiveSandboxes()
  const activeSandboxes = allSandboxes.filter(sb => sb.agent === currentAgent)

  return {
    generatedAt: new Date().toISOString(),
    selectedWorkspace,
    currentAgent,
    activeAgentSessions: context.activeAgentSessions,
    workspaces: [selectedWorkspace],
    activeSandboxes,
    agents,
    permissionGroups,
    allCliRules,
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

  // Network egress check if a URL or network tool is referenced
  const urlMatch = /https?:\/\/([^/\s:]+)/.exec(trimmed)
  if (urlMatch) {
    const host = urlMatch[1].toLowerCase()
    const allEndpoints = report.agents.flatMap(a => a.endpoints)
    const matchedEp = allEndpoints.find(ep => ep.host.toLowerCase() === host)
    if (matchedEp) {
      sandboxChecks.push({
        layer: 'OpenShell mTLS Egress Proxy',
        status: 'pass',
        detail: `Host '${host}:${matchedEp.port}' is allowed (${matchedEp.access}) via ${matchedEp.policyName}.`,
      })
    } else {
      sandboxChecks.push({
        layer: 'OpenShell mTLS Egress Proxy',
        status: 'block',
        detail: `Host '${host}' is not in any allowed network_policies endpoint list; egress will be denied.`,
      })
    }
  }

  return {
    command: trimmed,
    verdict,
    summary,
    matchedRules,
    sandboxChecks,
  }
}
