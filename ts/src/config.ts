import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import {
  DEFAULT_SANDBOX_ENABLED as SHARED_DEFAULT_SANDBOX_ENABLED,
  DEFAULT_SANDBOX_IDLE_TIMEOUT_SEC as SHARED_DEFAULT_IDLE_TIMEOUT_SEC,
  getDefaultSandboxEnabled as getSharedDefaultSandboxEnabled,
  getSandboxIdleTimeoutSeconds as getSharedSandboxIdleTimeoutSeconds,
  getSandboxMode,
  getSandboxModeFilePath,
  pruneSandboxRegistryEntry,
  setDefaultSandboxEnabled as setSharedDefaultSandboxEnabled,
} from '../../orca-plugin/src/state/sandbox-mode.ts';
import {
  getSandboxRegistryFilePath,
  registerSandboxRegistryEntry,
} from '../../orca-plugin/src/state/sandbox-registry.ts';
import { resolveGitMainWorktreePath } from '../../orca-plugin/src/state/worktree-paths.ts';
import type { SandboxRegistryEntry as SharedSandboxRegistryEntry } from '../../orca-plugin/src/types.ts';

export const USER_HOME = os.homedir();
export const DEBUG_LOG_PATH = path.join(USER_HOME, '.orca', 'openshell-bridge.log');
export const DEFAULT_SANDBOX_ENABLED = SHARED_DEFAULT_SANDBOX_ENABLED;
export const DEFAULT_SANDBOX_IDLE_TIMEOUT_SEC = SHARED_DEFAULT_IDLE_TIMEOUT_SEC;

export type SandboxRegistryEntry = SharedSandboxRegistryEntry;

export interface SandboxIdleTimeoutLookup {
  sandboxName?: string;
  agentSessionId?: string;
  terminalId?: string;
}

export function getSandboxModePath(homeDir = USER_HOME): string {
  return getSandboxModeFilePath(homeDir);
}

export function getDefaultSandboxEnabled(homeDir = USER_HOME): boolean {
  return getSharedDefaultSandboxEnabled(homeDir);
}

export function setDefaultSandboxEnabled(enabled: boolean, homeDir = USER_HOME): boolean {
  return setSharedDefaultSandboxEnabled(enabled, homeDir);
}

export function getSandboxIdleTimeoutSeconds(
  homeDir = USER_HOME,
  lookup?: SandboxIdleTimeoutLookup
): number {
  return getSharedSandboxIdleTimeoutSeconds(lookup, homeDir, true);
}

export function resolveGitMainWorktree(dirPath: string): string | null {
  return resolveGitMainWorktreePath(dirPath);
}

export function isSandboxModeEnabled(
  homeDir = USER_HOME,
  workspacePath = process.cwd(),
  workspaceId?: string
): boolean {
  if (process.env.ORCA_OPENSHELL_FORCE_SANDBOX === '1') return true;
  if (process.env.OPENSHELL_SANDBOX_DISABLED === '1') return false;
  if (workspacePath && path.basename(workspacePath).startsWith('orca-chat-name-')) {
    return false;
  }
  return getSandboxMode({ workspacePath, workspaceId }, homeDir).enabled;
}

export function logDebug(message: string): void {
  try {
    fs.mkdirSync(path.dirname(DEBUG_LOG_PATH), { recursive: true });
    const timestamp = new Date().toISOString().replace('T', ' ').slice(0, 19);
    fs.appendFileSync(DEBUG_LOG_PATH, `[${timestamp}] [PID ${process.pid}] ${message}\n`);
  } catch {
    // Ignore logging failures to never block the main bridge
  }
}

/**
 * Discovers the git project root or falls back to process.cwd()
 */
export function detectProjectRoot(cwd = process.cwd()): string {
  try {
    const stdout = execFileSync('git', ['-C', cwd, 'rev-parse', '--show-toplevel'], {
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    if (stdout.trim()) {
      return stdout.trim();
    }
  } catch {
    // Not a git repository
  }
  return cwd;
}

/**
 * Generates an OpenShell sandbox identifier conforming to the <=19 char requirement.
 */
export function generateSandboxName(prefix: string, projectName: string, pid = process.pid): string {
  const safeProj = projectName.replace(/[^a-zA-Z0-9_-]/g, '-').toLowerCase();
  const truncated = safeProj.slice(0, 8).replace(/^-+|-+$/g, '') || 'ws';
  const suffix = `${(pid % 1000).toString(36)}${randomBytes(3).toString('hex')}`;
  return `${prefix}-${truncated.slice(0, 6)}-${suffix}`.slice(0, 19);
}

/**
 * Finds the native host binary for fallback and fast paths.
 */
export function findHostBinary(name: string): string | null {
  const pathDirs = (process.env.PATH || '').split(path.delimiter);
  for (const dir of pathDirs) {
    const candidate = path.join(dir, name);
    try {
      if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
        const real = fs.realpathSync(candidate);
        if (!real.endsWith('-bridge.py') && !real.endsWith('-box') && !real.endsWith('.bundle.js')) {
          return candidate;
        }
      }
    } catch {
      // Continue
    }
  }

  const user = process.env.USER || '';
  const standardFallbacks = [
    `/etc/profiles/per-user/${user}/bin/${name}`,
    `/run/current-system/sw/bin/${name}`,
    `/opt/homebrew/bin/${name}`,
    `/usr/local/bin/${name}`,
    `/usr/bin/${name}`,
  ];

  for (const candidate of standardFallbacks) {
    try {
      if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
        return candidate;
      }
    } catch {
      // Continue
    }
  }

  return null;
}

export function getSandboxRegistryPath(homeDir = USER_HOME): string {
  return getSandboxRegistryFilePath(homeDir);
}

export function registerSandboxSession(
  input: Omit<SandboxRegistryEntry, 'createdAt' | 'updatedAt'> & { createdAt?: string },
  homeDir = USER_HOME
): void {
  if (!input.sandboxName) return;
  registerSandboxRegistryEntry(input, homeDir);
}

export function unregisterSandboxSession(sandboxName: string, homeDir = USER_HOME): void {
  if (!sandboxName) return;
  pruneSandboxRegistryEntry(sandboxName, homeDir);
}

function readGitConfigValue(key: string, cwd?: string): string | null {
  try {
    const args = cwd ? ['-C', cwd, 'config', '--get', key] : ['config', '--get', key];
    const out = execFileSync('git', args, {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 1500,
    }).trim();
    return out || null;
  } catch {
    return null;
  }
}

function escapeGitConfigValue(val: string): string {
  return val.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/[\r\n]+/g, ' ').trim();
}

/**
 * Builds the staged `/sandbox/.gitconfig` content for OpenShell sandboxes:
 * 1. Marks all mounted worktrees as safe (`safe.directory = *`).
 * 2. Rewrites SSH git remotes (`git@github.com:`, `git@gitlab.com:`) to HTTPS so git operations
 *    inside the sandbox route through the OpenShell L7 HTTPS proxy instead of failing on port 22 / missing SSH keys.
 * 3. Propagates non-secret host git author identity (`user.name` and `user.email`) so in-sandbox commits succeed.
 */
export function buildStagedGitConfig(
  projectRoot?: string,
  overrides?: { userName?: string | null; userEmail?: string | null }
): string {
  const userName =
    overrides?.userName !== undefined
      ? overrides.userName
      : readGitConfigValue('user.name', projectRoot) || readGitConfigValue('user.name');
  const userEmail =
    overrides?.userEmail !== undefined
      ? overrides.userEmail
      : readGitConfigValue('user.email', projectRoot) || readGitConfigValue('user.email');

  const lines: string[] = [
    '[safe]',
    '\tdirectory = *',
    '[url "https://github.com/"]',
    '\tinsteadOf = git@github.com:',
    '\tinsteadOf = ssh://git@github.com/',
    '[url "https://gitlab.com/"]',
    '\tinsteadOf = git@gitlab.com:',
    '\tinsteadOf = ssh://git@gitlab.com/',
  ];

  if (userName || userEmail) {
    lines.push('[user]');
    if (userName) lines.push(`\tname = "${escapeGitConfigValue(userName)}"`);
    if (userEmail) lines.push(`\temail = "${escapeGitConfigValue(userEmail)}"`);
  }

  return lines.join('\n') + '\n';
}
