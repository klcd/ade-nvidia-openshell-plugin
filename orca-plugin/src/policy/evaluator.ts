import type {
  CommandEvaluationResult,
  L7PolicySuggestion,
  PolicyInspectionReport,
} from '../types.ts'

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
export function evaluateCommandPolicy(
  command: string,
  report: PolicyInspectionReport
): CommandEvaluationResult {
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
