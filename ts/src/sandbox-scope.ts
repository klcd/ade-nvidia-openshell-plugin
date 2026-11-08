import fs from 'node:fs';
import path from 'node:path';
import type { OpenShellPolicy } from './types.js';

const WORKSPACE_WRITE_ENV = 'ORCA_SANDBOX_WRITE_PATHS';

/**
 * Returns null for the legacy full-workspace mode. Paseo agents default to an
 * empty write allowlist so they cannot edit the shared workspace implicitly.
 */
export function getWorkspaceWritePaths(projectRoot: string): string[] | null {
  const encoded = process.env[WORKSPACE_WRITE_ENV];
  if (encoded === undefined) {
    return process.env.PASEO_AGENT_ID ? [] : null;
  }

  let value: unknown;
  try {
    value = JSON.parse(encoded);
  } catch {
    throw new Error(`${WORKSPACE_WRITE_ENV} must be a JSON array of relative paths`);
  }
  if (!Array.isArray(value) || !value.every(item => typeof item === 'string')) {
    throw new Error(`${WORKSPACE_WRITE_ENV} must be a JSON array of relative paths`);
  }
  if (value.length > 200) throw new Error(`${WORKSPACE_WRITE_ENV} may contain at most 200 paths`);

  const normalized = new Set<string>();
  for (const candidate of value as string[]) {
    if (!candidate || path.isAbsolute(candidate) || candidate.includes('\0')) {
      throw new Error(`Invalid workspace write path: ${candidate}`);
    }
    const rel = path.normalize(candidate);
    if (rel === '.' || rel === '..' || rel.startsWith(`..${path.sep}`)) {
      throw new Error(`Workspace write path must stay inside the project: ${candidate}`);
    }
    if (rel === '.git' || rel.startsWith(`.git${path.sep}`)) {
      throw new Error('Workspace write scopes cannot include .git metadata');
    }

    const absolute = path.resolve(projectRoot, rel);
    if (!absolute.startsWith(`${path.resolve(projectRoot)}${path.sep}`)) {
      throw new Error(`Workspace write path escapes the project: ${candidate}`);
    }
    let cursor = path.resolve(projectRoot);
    for (const part of rel.split(path.sep)) {
      cursor = path.join(cursor, part);
      const stat = fs.lstatSync(cursor);
      if (stat.isSymbolicLink()) {
        throw new Error(`Workspace write scopes cannot traverse symlinks: ${candidate}`);
      }
    }
    if (!fs.statSync(absolute).isFile() && !fs.statSync(absolute).isDirectory()) {
      throw new Error(`Workspace write path must be a file or directory: ${candidate}`);
    }
    normalized.add(rel);
  }

  const paths = [...normalized].sort();
  for (let i = 0; i < paths.length; i++) {
    if (paths.some((other, j) => i !== j && paths[i]!.startsWith(`${other}${path.sep}`))) {
      throw new Error('Workspace write scopes cannot contain a path and its descendant');
    }
  }
  return paths;
}

/** Restrict project writes while leaving the agent's private home config writable. */
export function applyWorkspaceWriteScope(
  policy: OpenShellPolicy,
  projectName: string,
  agentHomePath: '.claude' | '.codex' | '.gemini',
  writePaths: string[]
): void {
  const filesystem = policy.filesystem_policy ??= { read_only: [], read_write: [] };
  const sandboxRoot = '/sandbox';
  const workspaceRoot = path.posix.join(sandboxRoot, projectName);

  filesystem.include_workdir = false;
  filesystem.read_only = (filesystem.read_only ?? []).filter(p => p !== sandboxRoot && !p.startsWith(`${sandboxRoot}/`));
  filesystem.read_write = (filesystem.read_write ?? []).filter(p => p !== sandboxRoot && !p.startsWith(`${sandboxRoot}/`));
  filesystem.read_only.push(sandboxRoot);
  filesystem.read_write.push(path.posix.join(sandboxRoot, agentHomePath));
  if (agentHomePath === '.claude') filesystem.read_write.push('/sandbox/.claude.json');

  for (const rel of writePaths) {
    filesystem.read_write.push(path.posix.join(workspaceRoot, ...rel.split(path.sep)));
  }
  filesystem.read_only = [...new Set(filesystem.read_only)];
  filesystem.read_write = [...new Set(filesystem.read_write)];
  policy.landlock ??= { compatibility: 'hard_requirement' };
  policy.landlock.compatibility = 'hard_requirement';
}

export function getExtraProviderNames(): string[] {
  const encoded = process.env.ORCA_SANDBOX_EXTRA_PROVIDERS;
  if (!encoded) return [];
  let value: unknown;
  try {
    value = JSON.parse(encoded);
  } catch {
    throw new Error('ORCA_SANDBOX_EXTRA_PROVIDERS must be a JSON array of provider names');
  }
  if (!Array.isArray(value) || !value.every(item => typeof item === 'string' && /^[a-z0-9][a-z0-9-]*$/.test(item))) {
    throw new Error('ORCA_SANDBOX_EXTRA_PROVIDERS must contain valid provider names');
  }
  return [...new Set(value as string[])];
}
