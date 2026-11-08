// Orca invokes this hook for terminal agent launches, including worker-start.
import type { OrcaWorkerApi } from 'orca/worker'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

const wrappers: Record<string, string> = {
  codex: 'codex-box',
  claude: 'claude-box',
  antigravity: 'agy-box',
  agy: 'agy-box',
}

const allowedExecutables: Record<string, string[]> = {
  codex: ['codex'],
  claude: ['claude'],
  antigravity: ['antigravity', 'agy'],
  agy: ['antigravity', 'agy'],
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`
}

/** Preserve Orca's arguments and prompt while replacing the first command token. */
export function bridgeCommand(agent: string, command: string, binDir: string): string | null {
  const wrapper = wrappers[agent]
  if (!wrapper) return null
  const executable = path.join(binDir, wrapper)
  if (!fs.existsSync(executable) || !fs.statSync(executable).isFile()) {
    throw new Error(`OpenShell bridge wrapper is missing: ${executable}`)
  }
  const match = /^(\s*)([\w./-]+)(?=\s|$)/.exec(command)
  const allowed = allowedExecutables[agent] || [agent]
  if (!match || !allowed.includes(path.basename(match[2]))) {
    throw new Error(`Unexpected ${agent} launch command; refusing an unverified rewrite`)
  }
  return `${match[1]}${shellQuote(executable)}${command.slice(match[0].length)}`
}

export default function activate(orca: OrcaWorkerApi): void {
  orca.hooks.on('agent.launch.before', (event, next) => {
    if (!(event.agent in wrappers)) return next()
    try {
      const binDir = process.env.ORCA_OPENSHELL_BRIDGE_BIN_DIR || path.join(os.homedir(), '.local', 'bin')
      const command = bridgeCommand(event.agent, event.command, binDir)
      if (!command) return { deny: 'No OpenShell bridge wrapper is configured for this agent' }
      const policyDir = process.env.ORCA_OPENSHELL_POLICY_DIR || path.join(os.homedir(), '.agents', 'orca-openshell-policies')
      let policyFile = path.join(policyDir, `${event.agent}.json`)
      if (!fs.existsSync(policyFile)) {
        if (event.agent === 'antigravity') policyFile = path.join(policyDir, 'agy.json')
        else if (event.agent === 'agy') policyFile = path.join(policyDir, 'antigravity.json')
      }
      if (!fs.existsSync(policyFile)) return { deny: `OpenShell policy is missing: ${policyFile}` }
      const safeEnv = Object.fromEntries(Object.entries(event.env).filter(([key]) => !key.startsWith('OPENSHELL_BRIDGE_')))
      orca.log(`OpenShell bridge selected for ${event.agent} in ${event.workspaceId ?? 'unknown workspace'}`)
      return next({ ...event, command, env: {
        ...safeEnv,
        OPENSHELL_BRIDGE_REQUIRED: '1',
        OPENSHELL_BRIDGE_POLICY_FILE: policyFile,
        ...(event.terminalId && event.workspaceId ? {
          OPENSHELL_BRIDGE_TERMINAL_ID: event.terminalId,
          OPENSHELL_BRIDGE_WORKSPACE_ID: event.workspaceId,
        } : {}),
      } })
    } catch (error) {
      return { deny: String(error) }
    }
  })
}
