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

export interface OrcaWorktreePsEntry {
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

export interface SandboxModeFileData {
  enabled?: boolean
  updatedAt?: string
  idleTimeoutSeconds?: number
  tabIdleTimeouts?: Record<string, { seconds: number; updatedAt: string }>
  worktrees?: Record<string, { enabled: boolean; updatedAt: string; workspaceId?: string }>
  orcaWorkspaces?: Record<string, { enabled: boolean; updatedAt: string; path?: string }>
  parentPaths?: Record<string, string>
}

export interface SandboxModeQueryOptions {
  workspacePath?: string
  workspaceId?: string
  parentPaths?: Record<string, string>
}

export interface SandboxIdleTimeoutOptions {
  sandboxName?: string | null
  agentSessionId?: string | null
  terminalId?: string | null
  paneKey?: string | null
  workspacePath?: string | null
  agent?: string | null
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

export interface CurrentOrcaContext {
  workspace: WorkspaceEntry
  currentAgent: 'claude' | 'codex' | 'antigravity'
  activeAgentSessions: ActiveAgentSessionInfo[]
}

export interface ParsedOpenShellPolicy {
  landlock?: string
  includeWorkdir?: boolean
  readOnly: string[]
  readWrite: string[]
  endpoints: NetworkEndpointRule[]
}

export function normalizeAgentId(raw?: string | null): 'claude' | 'codex' | 'antigravity' | null {
  if (!raw) return null
  const lower = raw.toLowerCase().trim()
  if (lower === 'claude' || lower === 'claude-code' || lower === 'claude-box') return 'claude'
  if (lower === 'codex' || lower === 'codex-box') return 'codex'
  if (lower === 'antigravity' || lower === 'agy' || lower === 'agy-box' || lower === 'gemini') return 'antigravity'
  return null
}

export function inferSandboxAgent(name: string): string {
  if (name.startsWith('cc-')) return 'claude'
  if (name.startsWith('cx-')) return 'codex'
  if (name.startsWith('ag-')) return 'antigravity'
  return 'custom'
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
