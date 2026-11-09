import fs from 'node:fs'
import path from 'node:path'
import type { OrcaWorktreePsEntry } from '../types.ts'

let cachedOrcaWorktrees: OrcaWorktreePsEntry[] = []

export function getCachedOrcaWorktrees(): OrcaWorktreePsEntry[] {
  return cachedOrcaWorktrees
}

export function setCachedOrcaWorktrees(worktrees: OrcaWorktreePsEntry[]): void {
  cachedOrcaWorktrees = worktrees
}

export function normalizeWorktreePath(rawPath?: string | null): string {
  if (!rawPath) return ''
  try {
    return fs.existsSync(rawPath) ? fs.realpathSync(rawPath) : path.resolve(rawPath)
  } catch {
    return path.resolve(rawPath)
  }
}

export function resolveGitMainWorktreePath(dirPath: string): string | null {
  try {
    const dotGit = path.join(dirPath, '.git')
    if (!fs.existsSync(dotGit)) return null
    const stat = fs.lstatSync(dotGit)
    if (!stat.isFile()) return null
    const content = fs.readFileSync(dotGit, 'utf8').trim()
    if (!content.startsWith('gitdir:')) return null
    const rawGitDir = content.slice('gitdir:'.length).trim()
    const absGitDir = path.resolve(dirPath, rawGitDir)
    const worktreesSegment = `${path.sep}.git${path.sep}worktrees${path.sep}`
    const idx = absGitDir.indexOf(worktreesSegment)
    if (idx > 0) {
      return normalizeWorktreePath(absGitDir.slice(0, idx))
    }
    return null
  } catch {
    return null
  }
}

export function extractPathFromWorkspaceId(workspaceId?: string | null): string {
  if (!workspaceId) return ''
  const sepIdx = workspaceId.indexOf('::/')
  if (sepIdx >= 0) {
    return workspaceId.slice(sepIdx + 2)
  }
  return ''
}

export function resolveWorkspacePathById(workspaceId?: string | null): string | undefined {
  if (!workspaceId) return undefined
  const fromId = extractPathFromWorkspaceId(workspaceId)
  if (fromId) return fromId
  for (const w of cachedOrcaWorktrees) {
    if (!w.path) continue
    if (
      w.worktreeId === workspaceId ||
      w.worktreeInstanceId === workspaceId ||
      (w.worktreeInstanceId && `wt2:local:${w.worktreeInstanceId}` === workspaceId)
    ) {
      return w.path
    }
  }
  return undefined
}

export function collectOrcaWorktreeParentMap(worktrees: OrcaWorktreePsEntry[]): Record<string, string> {
  const byId = new Map<string, string>()
  for (const w of worktrees) {
    if (!w.path) continue
    const norm = normalizeWorktreePath(w.path)
    if (w.worktreeId) byId.set(w.worktreeId, norm)
    if (w.worktreeInstanceId) {
      byId.set(w.worktreeInstanceId, norm)
      byId.set(`wt2:local:${w.worktreeInstanceId}`, norm)
    }
  }
  const parents: Record<string, string> = {}
  for (const w of worktrees) {
    if (!w.path) continue
    const normPath = normalizeWorktreePath(w.path)
    if (w.parentWorktreeId) {
      const parentRaw = byId.get(w.parentWorktreeId) || extractPathFromWorkspaceId(w.parentWorktreeId)
      const normParent = normalizeWorktreePath(parentRaw)
      if (normParent && normParent !== normPath) {
        parents[normPath] = normParent
      }
    }
    for (const childId of w.childWorktreeIds ?? []) {
      const childRaw = byId.get(childId) || extractPathFromWorkspaceId(childId)
      const normChild = normalizeWorktreePath(childRaw)
      if (normChild && normChild !== normPath) {
        parents[normChild] = normPath
      }
    }
  }
  return parents
}

export function doesPathDescendFrom(
  candidatePath: string,
  targetAncestor: string,
  parentMap: Map<string, string>
): boolean {
  const visited = new Set<string>()
  let curr = normalizeWorktreePath(candidatePath)
  const normAncestor = normalizeWorktreePath(targetAncestor)
  if (!curr || !normAncestor || curr === normAncestor) return false

  while (curr && !visited.has(curr)) {
    visited.add(curr)
    if (curr === normAncestor) return true
    if (curr.startsWith(normAncestor + path.sep)) return true

    let nextParent = parentMap.get(curr) || resolveGitMainWorktreePath(curr) || ''
    let anc = path.dirname(curr)
    while (anc && anc !== curr && anc !== path.dirname(anc)) {
      if (anc === normAncestor) return true
      if (!nextParent) {
        nextParent = parentMap.get(anc) || resolveGitMainWorktreePath(anc) || ''
      }
      anc = path.dirname(anc)
    }
    if (nextParent && !visited.has(nextParent)) {
      curr = nextParent
      continue
    }
    break
  }
  return false
}
