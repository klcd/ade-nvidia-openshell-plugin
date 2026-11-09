import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import type {
  CliPermissionRule,
  NativeAgentSyncStatus,
  PermissionGroupSummary,
} from '../types.ts'

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

export function loadPermissionGroups(
  workspacePath: string,
  homeDir = os.homedir()
): PermissionGroupSummary[] {
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
