import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import type { OpenShellPolicy } from '../types.js';
import { detectProjectRoot, USER_HOME } from '../config.js';
import { discoverAndMergePolicies, mergePolicies, mergeTwoPolicies, parsePolicyFile } from '../policy.js';
import { applyWorkspaceWriteScope, getWorkspaceWritePaths } from '../sandbox-scope.js';

export interface AgyChatSandboxState {
  sandboxName: string;
  projectRoot: string;
  projectName: string;
  containerRoot: string;
  sshConfigPath: string;
  sshControlPath: string;
  sshHost: string;
  harnessPid: number;
  daemonPid: number;
  agentSessionId?: string;
  createdAt: string;
  ready: boolean;
  hibernated?: boolean;
}

export function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

export function isPidAlive(pid: number): boolean {
  if (!Number.isFinite(pid) || pid <= 1) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

export function writeAtomicState(statePath: string, state: AgyChatSandboxState): void {
  const tmpStatePath = `${statePath}.${process.pid}.tmp`;
  fs.writeFileSync(tmpStatePath, JSON.stringify(state, null, 2), { mode: 0o600 });
  fs.renameSync(tmpStatePath, statePath);
}

export function touchAgyActivity(sessionDir: string, nowMs = Date.now()): void {
  try {
    fs.mkdirSync(sessionDir, { recursive: true, mode: 0o700 });
    fs.writeFileSync(path.join(sessionDir, 'activity.stamp'), String(nowMs), { mode: 0o600 });
  } catch {}
}

export function readLastAgyActivity(sessionDir: string): number {
  try {
    const stampPath = path.join(sessionDir, 'activity.stamp');
    if (!fs.existsSync(stampPath)) return 0;
    const val = Number(fs.readFileSync(stampPath, 'utf8').trim());
    return Number.isFinite(val) && val > 0 ? val : 0;
  } catch {
    return 0;
  }
}

export function acquireAgyExecLock(sessionDir: string, pid = process.pid): () => void {
  const execsDir = path.join(sessionDir, 'active-execs');
  const lockFile = path.join(execsDir, `${pid}-${Date.now()}.lock`);
  try {
    fs.mkdirSync(execsDir, { recursive: true, mode: 0o700 });
    fs.writeFileSync(lockFile, String(pid), { mode: 0o600 });
  } catch {}
  return () => {
    try {
      fs.unlinkSync(lockFile);
    } catch {}
  };
}

export function hasActiveAgyExecs(sessionDir: string): boolean {
  const execsDir = path.join(sessionDir, 'active-execs');
  if (!fs.existsSync(execsDir)) return false;
  try {
    let active = false;
    for (const entry of fs.readdirSync(execsDir)) {
      if (!entry.endsWith('.lock')) continue;
      const fullPath = path.join(execsDir, entry);
      try {
        const lockPid = Number(fs.readFileSync(fullPath, 'utf8').trim());
        if (isPidAlive(lockPid)) {
          active = true;
        } else {
          try {
            fs.unlinkSync(fullPath);
          } catch {}
        }
      } catch {}
    }
    return active;
  } catch {
    return false;
  }
}

export function getAgySessionDir(sessionKey: string): string {
  const safeSessionKey = sessionKey.replace(/[^a-zA-Z0-9_.-]/g, '_');
  const compactKey =
    safeSessionKey.length > 24
      ? `${safeSessionKey.slice(0, 11)}-${createHash('sha256').update(safeSessionKey).digest('hex').slice(0, 12)}`
      : safeSessionKey;
  const baseDir = process.env.ORCA_AG_SESSIONS_DIR || path.join(USER_HOME, '.orca', 'ag');
  return path.join(baseDir, compactKey);
}

export function resolveAgyProjectRoot(cwd: string, harnessPid: number): string {
  if (process.env.AG_HOST_WORKDIR && fs.existsSync(process.env.AG_HOST_WORKDIR)) {
    return detectProjectRoot(process.env.AG_HOST_WORKDIR);
  }
  const geminiHome =
    process.env.GEMINI_HOME ||
    path.join(USER_HOME, 'Library', 'Application Support', 'orca', 'antigravity-chat');
  const isInternalAgyDir =
    cwd.startsWith(geminiHome) ||
    cwd.includes('/antigravity-chat/') ||
    cwd.includes('/antigravity-cli/skills') ||
    cwd.startsWith('/tmp/oacp-');

  if (!isInternalAgyDir && fs.existsSync(cwd)) {
    return detectProjectRoot(cwd);
  }

  if (harnessPid > 1) {
    try {
      const out = execFileSync('lsof', ['-a', '-p', String(harnessPid), '-d', 'cwd', '-Fn'], {
        encoding: 'utf8',
        timeout: 2000,
        stdio: ['ignore', 'pipe', 'ignore'],
      });
      for (const line of out.split(/\r?\n/)) {
        if (line.startsWith('n/')) {
          const candidate = line.slice(1).trim();
          if (candidate && fs.existsSync(candidate) && !candidate.startsWith(geminiHome)) {
            return detectProjectRoot(candidate);
          }
        }
      }
    } catch {}
  }

  try {
    const out = execFileSync('orca', ['worktree', 'current', '--json'], {
      encoding: 'utf8',
      timeout: 2500,
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    const parsed = JSON.parse(out) as { result?: { worktree?: { path?: string } } };
    const wtPath = parsed.result?.worktree?.path;
    if (wtPath && fs.existsSync(wtPath)) {
      return detectProjectRoot(wtPath);
    }
  } catch {}

  return detectProjectRoot(cwd);
}

export function translateAgyCommandAndCwd(
  commandLine: string,
  hostCwd: string,
  projectRoot: string,
  containerRoot: string
): { translatedCommand: string; containerCwd: string } {
  let containerCwd = containerRoot;
  const normalizedHostCwd = path.resolve(hostCwd);
  const normalizedProjectRoot = path.resolve(projectRoot);
  if (
    normalizedHostCwd === normalizedProjectRoot ||
    normalizedHostCwd.startsWith(normalizedProjectRoot + path.sep)
  ) {
    const rel = path.relative(normalizedProjectRoot, normalizedHostCwd);
    containerCwd = rel
      ? path.posix.join(containerRoot, ...rel.split(path.sep))
      : containerRoot;
  }

  const escapedRoot = normalizedProjectRoot.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const translatedCommand = commandLine.replace(new RegExp(escapedRoot, 'g'), containerRoot);
  return { translatedCommand, containerCwd };
}

export function loadMergedAgyPolicy(projectRoot: string, projectName: string): OpenShellPolicy {
  const defaultOrcaPolicy = path.join(
    USER_HOME,
    '.orca',
    'plugins',
    'openshell-bridge',
    'policies',
    'orca-standard.yaml'
  );
  const fallbackAntigravityPolicy = path.join(
    USER_HOME,
    '.agents',
    'orca-openshell-policies',
    'antigravity.json'
  );
  const explicitPolicy =
    process.env.OPENSHELL_BRIDGE_POLICY_FILE ??
    process.env.ORCA_OPENSHELL_POLICY_FILE ??
    (fs.existsSync(defaultOrcaPolicy)
      ? defaultOrcaPolicy
      : fs.existsSync(fallbackAntigravityPolicy)
        ? fallbackAntigravityPolicy
        : undefined);

  const projectPolicy = mergePolicies([path.join(projectRoot, '.agents', 'policies')]);
  const policy: OpenShellPolicy = explicitPolicy
    ? mergeTwoPolicies(
        parsePolicyFile(explicitPolicy) ?? {
          version: 1,
          filesystem_policy: {
            include_workdir: true,
            read_only: ['/bin', '/usr', '/lib', '/proc', '/etc', '/dev/urandom'],
            read_write: ['/tmp', '/dev/null'],
          },
        },
        projectPolicy
      )
    : discoverAndMergePolicies(projectRoot) ?? {
        version: 1,
        filesystem_policy: {
          include_workdir: true,
          read_only: ['/bin', '/usr', '/lib', '/proc', '/etc', '/dev/urandom'],
          read_write: ['/tmp', '/dev/null'],
        },
      };

  policy.filesystem_policy ??= {
    include_workdir: true,
    read_only: ['/bin', '/usr', '/lib', '/proc', '/etc', '/dev/urandom'],
    read_write: ['/tmp', '/dev/null'],
  };
  policy.landlock = { compatibility: 'hard_requirement' };
  policy.network_middlewares ??= {};
  policy.network_middlewares.outbound_token_redaction ??= {
    name: 'Redact provider-shaped API tokens in request bodies',
    middleware: 'openshell/regex',
    order: 10,
    config: { mode: 'redact' },
    on_error: 'fail_closed',
    endpoints: { include: ['**'] },
  };

  const workspaceWritePaths = getWorkspaceWritePaths(projectRoot);
  if (workspaceWritePaths !== null) {
    applyWorkspaceWriteScope(policy, projectName, '.gemini', workspaceWritePaths);
  }
  return policy;
}
