import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import type { SessionEgressEntry } from '../types.ts'
import { readJsonSafe, withStateLock, writeJsonAtomic } from './file-lock.ts'

export function getSessionEgressFilePath(homeDir = os.homedir()): string {
  if (process.env.ORCA_OPENSHELL_SESSION_EGRESS_FILE) {
    return process.env.ORCA_OPENSHELL_SESSION_EGRESS_FILE
  }
  return path.join(homeDir, '.config', 'orca-openshell', 'session-egress.json')
}

export function readSessionEgressEntries(homeDir = os.homedir()): SessionEgressEntry[] {
  const filePath = getSessionEgressFilePath(homeDir)
  if (!fs.existsSync(filePath)) return []
  const parsed = readJsonSafe<{ entries?: SessionEgressEntry[] }>(filePath, {})
  return Array.isArray(parsed?.entries) ? parsed.entries : []
}

export function writeSessionEgressEntries(entries: SessionEgressEntry[], homeDir = os.homedir()): void {
  const filePath = getSessionEgressFilePath(homeDir)
  writeJsonAtomic(filePath, { entries })
}

export function recordSessionEgressRule(entry: SessionEgressEntry, homeDir = os.homedir()): void {
  const filePath = getSessionEgressFilePath(homeDir)
  withStateLock(filePath, () => {
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
  })
}

export function removeSessionEgressRule(
  criteria: {
    sandboxName?: string
    workspacePath?: string
    host: string
    port?: number
    method?: string
    path?: string
  },
  homeDir = os.homedir()
): boolean {
  const filePath = getSessionEgressFilePath(homeDir)
  return withStateLock(filePath, () => {
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
  })
}

export function pruneSandboxSessionEgress(sandboxName: string, homeDir = os.homedir()): void {
  if (!sandboxName) return
  const filePath = getSessionEgressFilePath(homeDir)
  withStateLock(filePath, () => {
    const entries = readSessionEgressEntries(homeDir)
    const filtered = entries.filter(e => e.sandboxName !== sandboxName)
    if (filtered.length !== entries.length) {
      writeSessionEgressEntries(filtered, homeDir)
    }
  })
}
