import { execFile, execFileSync } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import {
  inferSandboxAgent,
  type ActiveSandboxInfo,
  type SandboxDoctorCheck,
  type SandboxDoctorReport,
} from '../types.ts'
import { pruneSandboxRegistryEntry } from '../state/sandbox-mode.ts'
import { readSandboxRegistryMap } from '../state/sandbox-registry.ts'
import { pruneSandboxSessionEgress } from '../state/session-egress.ts'

let cachedSandboxes: ActiveSandboxInfo[] = []
let lastSandboxRefreshAt = 0
let sandboxRefreshInFlight: Promise<void> | null = null

export function getAugmentedPathDirs(homeDir = os.homedir()): string[] {
  const user = process.env.USER || path.basename(homeDir) || ''
  const currentDirs = (process.env.PATH || '').split(path.delimiter).filter(Boolean)
  const fallbackDirs = [
    path.join(homeDir, '.local', 'bin'),
    path.join(homeDir, '.nix-profile', 'bin'),
    user ? `/etc/profiles/per-user/${user}/bin` : '',
    '/run/current-system/sw/bin',
    '/nix/var/nix/profiles/default/bin',
    '/opt/homebrew/bin',
    '/usr/local/bin',
    '/usr/bin',
    '/bin',
  ].filter(Boolean)

  const seen = new Set<string>()
  const merged: string[] = []
  for (const dir of [...currentDirs, ...fallbackDirs]) {
    if (!seen.has(dir)) {
      seen.add(dir)
      merged.push(dir)
    }
  }
  return merged
}

export function getAugmentedEnv(homeDir = os.homedir()): NodeJS.ProcessEnv {
  return {
    ...process.env,
    PATH: getAugmentedPathDirs(homeDir).join(path.delimiter),
  }
}

export function resolveOpenShellBinary(homeDir = os.homedir()): string {
  if (process.env.ORCA_OPENSHELL_BIN && fs.existsSync(process.env.ORCA_OPENSHELL_BIN)) {
    return process.env.ORCA_OPENSHELL_BIN
  }
  for (const dir of getAugmentedPathDirs(homeDir)) {
    const candidate = path.join(dir, 'openshell')
    try {
      if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
        return candidate
      }
    } catch {}
  }
  return 'openshell'
}

export function parseSandboxListOutput(out: string): ActiveSandboxInfo[] {
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

  const openshellBin = resolveOpenShellBinary()
  const env = getAugmentedEnv()
  sandboxRefreshInFlight = new Promise<void>((resolve) => {
    execFile(openshellBin, ['sandbox', 'list', '-o', 'json'], { timeout: 2500, env }, (err, stdout) => {
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

export function listActiveSandboxes(): ActiveSandboxInfo[] {
  void refreshActiveSandboxesCache()
  return cachedSandboxes
}

export async function pauseActiveSandbox(sandboxName: string): Promise<{ ok: boolean; message: string }> {
  const cleanName = String(sandboxName || '').trim()
  if (!/^[a-z0-9][a-z0-9-]{0,30}$/.test(cleanName)) {
    return { ok: false, message: `Invalid sandbox name "${sandboxName}".` }
  }
  const openshellBin = resolveOpenShellBinary()
  const env = getAugmentedEnv()
  return new Promise((resolve) => {
    execFile(openshellBin, ['sandbox', 'stop', cleanName], { timeout: 25000, env }, async (err, _stdout, stderr) => {
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
  const openshellBin = resolveOpenShellBinary()
  const env = getAugmentedEnv()
  return new Promise((resolve) => {
    execFile(openshellBin, ['sandbox', 'start', cleanName], { timeout: 35000, env }, async (err, _stdout, stderr) => {
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

const PRE_DELETE_SYNC_IGNORED_NAMES = new Set([
  '.git',
  'node_modules',
  '.orca-openshell-l7-requests',
])

function copyNewerOrModifiedTree(srcDir: string, dstDir: string): number {
  let syncedCount = 0
  if (!fs.existsSync(srcDir)) return 0
  for (const entry of fs.readdirSync(srcDir, { withFileTypes: true })) {
    if (PRE_DELETE_SYNC_IGNORED_NAMES.has(entry.name)) continue
    const srcPath = path.join(srcDir, entry.name)
    const dstPath = path.join(dstDir, entry.name)
    try {
      if (entry.isDirectory()) {
        fs.mkdirSync(dstPath, { recursive: true })
        syncedCount += copyNewerOrModifiedTree(srcPath, dstPath)
      } else if (entry.isFile()) {
        const srcBuf = fs.readFileSync(srcPath)
        const dstExists = fs.existsSync(dstPath)
        const differs = !dstExists || !fs.readFileSync(dstPath).equals(srcBuf)
        if (differs) {
          fs.mkdirSync(path.dirname(dstPath), { recursive: true })
          fs.writeFileSync(dstPath, srcBuf)
          syncedCount++
        }
      }
    } catch {}
  }
  return syncedCount
}

/**
 * Safety net before deleting a running sandbox container:
 * downloads `/sandbox/<projectName>` and syncs any uncommitted file modifications back to the host worktree.
 */
export function syncSandboxWorkspaceBeforeDelete(
  sandboxName: string,
  homeDir = os.homedir()
): number {
  const regEntry = readSandboxRegistryMap(homeDir).get(sandboxName)
  const workspacePath = regEntry?.workspacePath
  if (!workspacePath || !fs.existsSync(workspacePath)) return 0

  const sbInfo = cachedSandboxes.find(s => s.name === sandboxName)
  if (sbInfo && /stopped/i.test(sbInfo.phase || '')) {
    return 0
  }

  const projectName = path.basename(workspacePath)
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), `openshell-predelete-${sandboxName}-`))
  const openshellBin = resolveOpenShellBinary(homeDir)
  const env = getAugmentedEnv(homeDir)
  try {
    execFileSync(
      openshellBin,
      ['sandbox', 'download', sandboxName, `/sandbox/${projectName}`, tmpDir],
      { stdio: ['ignore', 'ignore', 'ignore'], timeout: 8000, env }
    )
    const nestedCandidate = path.join(tmpDir, projectName)
    const downloadRoot =
      fs.existsSync(nestedCandidate) && fs.statSync(nestedCandidate).isDirectory()
        ? nestedCandidate
        : tmpDir
    return copyNewerOrModifiedTree(downloadRoot, workspacePath)
  } catch {
    return 0
  } finally {
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true })
    } catch {}
  }
}

export async function stopActiveSandbox(sandboxName: string): Promise<{ ok: boolean; message: string }> {
  const cleanName = String(sandboxName || '').trim()
  if (!/^[a-z0-9][a-z0-9-]{0,30}$/.test(cleanName)) {
    return { ok: false, message: `Invalid sandbox name "${sandboxName}".` }
  }
  const syncedFiles = syncSandboxWorkspaceBeforeDelete(cleanName)
  const openshellBin = resolveOpenShellBinary()
  const env = getAugmentedEnv()
  return new Promise((resolve) => {
    execFile(openshellBin, ['sandbox', 'delete', cleanName], { timeout: 10000, env }, async (err, _stdout, stderr) => {
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
      const syncNote = syncedFiles > 0 ? ` (synced ${syncedFiles} modified file(s) to host worktree)` : ''
      resolve({ ok: true, message: `Deleted sandbox ${cleanName}${syncNote}.` })
    })
  })
}

export async function runSandboxDoctor(homeDir = os.homedir()): Promise<SandboxDoctorReport> {
  const checks: SandboxDoctorCheck[] = []
  const openshellBin = resolveOpenShellBinary(homeDir)
  const env = getAugmentedEnv(homeDir)

  // 1. OpenShell CLI binary
  let cliVersion = ''
  try {
    cliVersion = execFileSync(openshellBin, ['--version'], {
      encoding: 'utf8',
      timeout: 3000,
      stdio: ['ignore', 'pipe', 'pipe'],
      env,
    }).trim()
    checks.push({
      id: 'openshell-cli',
      label: 'OpenShell CLI',
      status: 'pass',
      detail: `${cliVersion || 'openshell'} (${openshellBin})`,
    })
  } catch (err: any) {
    checks.push({
      id: 'openshell-cli',
      label: 'OpenShell CLI',
      status: 'fail',
      detail: `Not found or failed to execute (${err?.message || 'missing openshell binary'})`,
    })
  }

  // 2. OpenShell Cluster / Gateway reachability
  let liveSandboxes: ActiveSandboxInfo[] = []
  try {
    const out = execFileSync(openshellBin, ['sandbox', 'list', '-o', 'json'], {
      encoding: 'utf8',
      timeout: 4000,
      stdio: ['ignore', 'pipe', 'pipe'],
      env,
    })
    liveSandboxes = parseSandboxListOutput(out)
    cachedSandboxes = liveSandboxes
    lastSandboxRefreshAt = Date.now()
    const readyCount = liveSandboxes.filter(s => /ready|running/i.test(s.phase)).length
    const stoppedCount = liveSandboxes.filter(s => /stopped/i.test(s.phase)).length
    checks.push({
      id: 'openshell-cluster',
      label: 'OpenShell Gateway',
      status: 'pass',
      detail: `Connected (${readyCount} running, ${stoppedCount} paused)`,
    })
  } catch (err: any) {
    checks.push({
      id: 'openshell-cluster',
      label: 'OpenShell Gateway',
      status: 'fail',
      detail: `Unreachable: ${String(err?.stderr || err?.message || err).trim()}`,
    })
  }

  // 3. Host bridge wrappers
  const binDir = process.env.ORCA_OPENSHELL_BRIDGE_BIN_DIR || path.join(homeDir, '.local', 'bin')
  const expectedWrappers = ['agent-box', 'claude-box', 'codex-box', 'agy-box']
  const missingWrappers = expectedWrappers.filter(w => !fs.existsSync(path.join(binDir, w)))
  if (missingWrappers.length === 0) {
    checks.push({
      id: 'host-wrappers',
      label: 'Host Bridge Wrappers',
      status: 'pass',
      detail: `Installed in ${binDir} (${expectedWrappers.join(', ')})`,
    })
  } else {
    checks.push({
      id: 'host-wrappers',
      label: 'Host Bridge Wrappers',
      status: 'fail',
      detail: `Missing in ${binDir}: ${missingWrappers.join(', ')} (run ./scripts/install-orca-host.sh)`,
    })
  }

  // 4. Base policy profiles
  const policyDir =
    process.env.ORCA_OPENSHELL_POLICY_DIR || path.join(homeDir, '.agents', 'orca-openshell-policies')
  const expectedPolicies = ['claude.json', 'codex.json', 'antigravity.json']
  const missingPolicies = expectedPolicies.filter(p => !fs.existsSync(path.join(policyDir, p)))
  if (missingPolicies.length === 0) {
    checks.push({
      id: 'base-policies',
      label: 'Agent L7 Policies',
      status: 'pass',
      detail: `Installed in ${policyDir} (${expectedPolicies.join(', ')})`,
    })
  } else {
    checks.push({
      id: 'base-policies',
      label: 'Agent L7 Policies',
      status: 'fail',
      detail: `Missing in ${policyDir}: ${missingPolicies.join(', ')}`,
    })
  }

  // 5. Registry vs live sandbox reconciliation
  const registryMap = readSandboxRegistryMap(homeDir)
  const liveNames = new Set(liveSandboxes.map(s => s.name))
  const staleRegistered: string[] = []
  if (checks.find(c => c.id === 'openshell-cluster')?.status === 'pass') {
    for (const sbName of registryMap.keys()) {
      if (!liveNames.has(sbName)) {
        staleRegistered.push(sbName)
        pruneSandboxRegistryEntry(sbName, homeDir)
        pruneSandboxSessionEgress(sbName, homeDir)
      }
    }
  }
  checks.push({
    id: 'registry-health',
    label: 'Session Registry',
    status: 'pass',
    detail:
      staleRegistered.length > 0
        ? `Pruned ${staleRegistered.length} stale registry entry(s): ${staleRegistered.join(', ')}`
        : `${registryMap.size} active session(s) tracked cleanly`,
  })

  return {
    ok: checks.every(c => c.status !== 'fail'),
    checkedAt: new Date().toISOString(),
    checks,
  }
}
