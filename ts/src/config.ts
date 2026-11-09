import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';

export const USER_HOME = os.homedir();
export const DEBUG_LOG_PATH = path.join(USER_HOME, '.orca', 'openshell-bridge.log');
export const DEFAULT_SANDBOX_IDLE_TIMEOUT_SEC = 300;

export function getSandboxModePath(homeDir = USER_HOME): string {
  if (process.env.ORCA_OPENSHELL_MODE_FILE) {
    return process.env.ORCA_OPENSHELL_MODE_FILE;
  }
  return path.join(homeDir, '.config', 'orca-openshell', 'sandbox-mode.json');
}

export interface SandboxIdleTimeoutLookup {
  sandboxName?: string;
  agentSessionId?: string;
  terminalId?: string;
}

export function getSandboxIdleTimeoutSeconds(
  homeDir = USER_HOME,
  lookup?: SandboxIdleTimeoutLookup
): number {
  const envRaw = process.env.ORCA_SANDBOX_IDLE_TIMEOUT_SEC;
  if (envRaw !== undefined && envRaw.trim() !== '') {
    const parsedEnv = Number(envRaw);
    if (Number.isFinite(parsedEnv) && parsedEnv >= 0) {
      return Math.floor(parsedEnv);
    }
  }
  const modePath = getSandboxModePath(homeDir);
  try {
    if (!fs.existsSync(modePath)) return DEFAULT_SANDBOX_IDLE_TIMEOUT_SEC;
    const parsed = JSON.parse(fs.readFileSync(modePath, 'utf8')) as {
      tabIdleTimeouts?: Record<string, { seconds?: number }>;
    };
    const tabMap = parsed.tabIdleTimeouts;
    if (!tabMap || typeof tabMap !== 'object') {
      return DEFAULT_SANDBOX_IDLE_TIMEOUT_SEC;
    }

    const sbName = lookup?.sandboxName?.trim();
    const sessId = (lookup?.agentSessionId ?? process.env.ORCA_AGENT_SESSION_ID ?? '').trim();
    const rawTerm = (
      lookup?.terminalId ??
      process.env.OPENSHELL_BRIDGE_TERMINAL_ID ??
      process.env.ORCA_TERMINAL_HANDLE ??
      ''
    ).trim();
    const termPrefix = rawTerm.includes(':') ? rawTerm.split(':')[0] : rawTerm;

    const candidateKeys: string[] = [];
    if (sbName) candidateKeys.push(`sandbox:${sbName}`);
    if (sessId) candidateKeys.push(`session:${sessId}`);
    if (termPrefix) candidateKeys.push(`terminal:${termPrefix}`);

    for (const key of candidateKeys) {
      const entry = tabMap[key];
      if (
        entry &&
        typeof entry.seconds === 'number' &&
        Number.isFinite(entry.seconds) &&
        entry.seconds >= 0
      ) {
        return Math.floor(entry.seconds);
      }
    }
    return DEFAULT_SANDBOX_IDLE_TIMEOUT_SEC;
  } catch {
    return DEFAULT_SANDBOX_IDLE_TIMEOUT_SEC;
  }
}

function normalizeWorktreeKey(rawPath?: string | null): string {
  if (!rawPath) return '';
  try {
    return fs.existsSync(rawPath) ? fs.realpathSync(rawPath) : path.resolve(rawPath);
  } catch {
    return path.resolve(rawPath);
  }
}

export function resolveGitMainWorktree(dirPath: string): string | null {
  try {
    const dotGit = path.join(dirPath, '.git');
    if (!fs.existsSync(dotGit)) return null;
    const stat = fs.lstatSync(dotGit);
    if (!stat.isFile()) return null;
    const content = fs.readFileSync(dotGit, 'utf8').trim();
    if (!content.startsWith('gitdir:')) return null;
    const rawGitDir = content.slice('gitdir:'.length).trim();
    const absGitDir = path.resolve(dirPath, rawGitDir);
    const worktreesSegment = `${path.sep}.git${path.sep}worktrees${path.sep}`;
    const idx = absGitDir.indexOf(worktreesSegment);
    if (idx > 0) {
      return normalizeWorktreeKey(absGitDir.slice(0, idx));
    }
    return null;
  } catch {
    return null;
  }
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
  const modePath = getSandboxModePath(homeDir);
  try {
    if (!fs.existsSync(modePath)) return true;
    const parsed = JSON.parse(fs.readFileSync(modePath, 'utf8')) as {
      enabled?: boolean;
      worktrees?: Record<string, { enabled?: boolean; workspaceId?: string }>;
      parentPaths?: Record<string, string>;
    };
    if (!parsed.worktrees) {
      return parsed.enabled !== false;
    }

    const worktreeMap = new Map<string, { enabled?: boolean; workspaceId?: string }>();
    for (const [k, v] of Object.entries(parsed.worktrees)) {
      if (v && typeof v === 'object') {
        worktreeMap.set(normalizeWorktreeKey(k), v);
      }
    }
    const parentMap = new Map<string, string>();
    for (const [k, v] of Object.entries(parsed.parentPaths || {})) {
      if (typeof v === 'string' && v) {
        parentMap.set(normalizeWorktreeKey(k), normalizeWorktreeKey(v));
      }
    }

    let startPath = normalizeWorktreeKey(workspacePath);
    if (!startPath && workspaceId) {
      const sepIdx = workspaceId.indexOf('::/');
      if (sepIdx >= 0) {
        startPath = normalizeWorktreeKey(workspaceId.slice(sepIdx + 2));
      } else {
        for (const info of worktreeMap.values()) {
          if (info?.workspaceId === workspaceId) {
            return info.enabled !== false;
          }
        }
      }
    }

    const visited = new Set<string>();
    let curr = startPath;
    while (curr && !visited.has(curr)) {
      visited.add(curr);
      const direct = worktreeMap.get(curr);
      if (direct !== undefined) {
        return direct.enabled !== false;
      }

      let nextParent = parentMap.get(curr) || resolveGitMainWorktree(curr) || '';
      let anc = path.dirname(curr);
      while (anc && anc !== curr && anc !== path.dirname(anc)) {
        const ancEntry = worktreeMap.get(anc);
        if (ancEntry !== undefined) {
          return ancEntry.enabled !== false;
        }
        if (!nextParent) {
          nextParent = parentMap.get(anc) || resolveGitMainWorktree(anc) || '';
        }
        anc = path.dirname(anc);
      }

      if (nextParent && !visited.has(nextParent)) {
        curr = nextParent;
        continue;
      }
      break;
    }
    return true;
  } catch {
    return true;
  }
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

export interface SandboxRegistryEntry {
  sandboxName: string;
  agent: 'claude' | 'codex' | 'antigravity';
  workspacePath: string;
  workspaceId?: string;
  terminalId?: string;
  agentSessionId?: string;
  pid: number;
  createdAt: string;
  updatedAt: string;
}

export function getSandboxRegistryPath(homeDir = USER_HOME): string {
  if (process.env.ORCA_OPENSHELL_REGISTRY_FILE) {
    return process.env.ORCA_OPENSHELL_REGISTRY_FILE;
  }
  return path.join(homeDir, '.config', 'orca-openshell', 'sandbox-registry.json');
}

function isRegistryPidAlive(pid: number): boolean {
  if (!Number.isFinite(pid) || pid <= 1) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

export function registerSandboxSession(
  input: Omit<SandboxRegistryEntry, 'createdAt' | 'updatedAt'> & { createdAt?: string },
  homeDir = USER_HOME
): void {
  if (!input.sandboxName) return;
  const regPath = getSandboxRegistryPath(homeDir);
  try {
    let existing: SandboxRegistryEntry[] = [];
    if (fs.existsSync(regPath)) {
      const parsed = JSON.parse(fs.readFileSync(regPath, 'utf8')) as { entries?: SandboxRegistryEntry[] };
      if (Array.isArray(parsed?.entries)) {
        existing = parsed.entries;
      }
    }
    const now = new Date().toISOString();
    const alive = existing.filter(
      e => e && e.sandboxName && e.sandboxName !== input.sandboxName && isRegistryPidAlive(e.pid)
    );
    const prev = existing.find(e => e?.sandboxName === input.sandboxName);
    const record: SandboxRegistryEntry = {
      sandboxName: input.sandboxName,
      agent: input.agent,
      workspacePath: normalizeWorktreeKey(input.workspacePath) || input.workspacePath,
      ...(input.workspaceId ? { workspaceId: input.workspaceId } : {}),
      ...(input.terminalId ? { terminalId: input.terminalId } : {}),
      ...(input.agentSessionId ? { agentSessionId: input.agentSessionId } : {}),
      pid: input.pid,
      createdAt: input.createdAt || prev?.createdAt || now,
      updatedAt: now,
    };
    alive.push(record);
    fs.mkdirSync(path.dirname(regPath), { recursive: true });
    const tmpPath = `${regPath}.${process.pid}.tmp`;
    fs.writeFileSync(tmpPath, JSON.stringify({ entries: alive }, null, 2) + '\n', 'utf8');
    fs.renameSync(tmpPath, regPath);
  } catch {}
}

export function unregisterSandboxSession(sandboxName: string, homeDir = USER_HOME): void {
  if (!sandboxName) return;
  const regPath = getSandboxRegistryPath(homeDir);
  try {
    if (fs.existsSync(regPath)) {
      const parsed = JSON.parse(fs.readFileSync(regPath, 'utf8')) as { entries?: SandboxRegistryEntry[] };
      if (Array.isArray(parsed?.entries)) {
        const next = parsed.entries.filter(
          e => e && e.sandboxName && e.sandboxName !== sandboxName && isRegistryPidAlive(e.pid)
        );
        const tmpPath = `${regPath}.${process.pid}.tmp`;
        fs.writeFileSync(tmpPath, JSON.stringify({ entries: next }, null, 2) + '\n', 'utf8');
        fs.renameSync(tmpPath, regPath);
      }
    }
  } catch {}
  try {
    const modePath = getSandboxModePath(homeDir);
    if (fs.existsSync(modePath)) {
      const parsed = JSON.parse(fs.readFileSync(modePath, 'utf8')) as {
        tabIdleTimeouts?: Record<string, unknown>;
        [k: string]: unknown;
      };
      const sbKey = `sandbox:${sandboxName}`;
      if (parsed?.tabIdleTimeouts && sbKey in parsed.tabIdleTimeouts) {
        delete parsed.tabIdleTimeouts[sbKey];
        const tmpMode = `${modePath}.${process.pid}.tmp`;
        fs.writeFileSync(tmpMode, JSON.stringify(parsed, null, 2) + '\n', 'utf8');
        fs.renameSync(tmpMode, modePath);
      }
    }
  } catch {}
}

