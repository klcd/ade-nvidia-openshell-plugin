import { execFile } from 'node:child_process'
import { inferSandboxAgent, type ActiveSandboxInfo } from '../types.ts'
import { pruneSandboxRegistryEntry } from '../state/sandbox-mode.ts'
import { pruneSandboxSessionEgress } from '../state/session-egress.ts'

let cachedSandboxes: ActiveSandboxInfo[] = []
let lastSandboxRefreshAt = 0
let sandboxRefreshInFlight: Promise<void> | null = null

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

export function listActiveSandboxes(): ActiveSandboxInfo[] {
  void refreshActiveSandboxesCache()
  return cachedSandboxes
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
