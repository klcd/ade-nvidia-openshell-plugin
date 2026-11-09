import fs from 'node:fs'
import path from 'node:path'
import type {
  L7HttpRule,
  NetworkEndpointRule,
  ParsedOpenShellPolicy,
} from '../types.ts'

export function compatibleCommandsForHost(host: string): string[] {
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
