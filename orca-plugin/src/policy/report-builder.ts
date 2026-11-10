import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import type {
  AddL7PolicyRequest,
  AgentProfilePolicy,
  CliPermissionRule,
  DelegationPolicySummary,
  L7HttpRule,
  NetworkEndpointRule,
  ParsedOpenShellPolicy,
  PolicyInspectionReport,
} from '../types.ts'
import {
  discoverCurrentOrcaContext,
  refreshOrcaContextCache,
  resolveCurrentTabSandbox,
} from '../context/orca-context.ts'
import {
  compatibleCommandsForHost,
  describeEndpointRelation,
  parseOpenShellPolicyFile,
} from '../parsers/openshell-policy.ts'
import { inspectNativeSync, loadPermissionGroups } from '../parsers/permission-yaml.ts'
import { listActiveSandboxes, refreshActiveSandboxesCache } from '../sandbox/sandbox-control.ts'
import {
  getDefaultSandboxEnabled,
  getSandboxIdleTimeoutSeconds,
  getSandboxMode,
} from '../state/sandbox-mode.ts'
import { readSessionEgressEntries, writeSessionEgressEntries } from '../state/session-egress.ts'
import { addL7Policy, DEFAULT_L7_WILDCARD_BINARIES } from './l7-mutator.ts'

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
        const bins = entry.binary === '*' ? DEFAULT_L7_WILDCARD_BINARIES : [entry.binary]
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
  const defaultSandboxEnabled = getDefaultSandboxEnabled(homeDir)

  return {
    generatedAt: new Date().toISOString(),
    sandboxEnabled: sandboxMode.enabled,
    defaultSandboxEnabled,
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
