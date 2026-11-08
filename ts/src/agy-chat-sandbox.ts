import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawn } from 'node:child_process';
import type { OpenShellPolicy } from './types.js';
import { detectProjectRoot, generateSandboxName, logDebug, USER_HOME } from './config.js';
import { discoverAndMergePolicies, mergePolicies, mergeTwoPolicies, parsePolicyFile } from './policy.js';
import { OpenShellSandbox } from './sandbox.js';
import { applyWorkspaceWriteScope, getExtraProviderNames, getWorkspaceWritePaths } from './sandbox-scope.js';

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
  createdAt: string;
  ready: boolean;
}

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

function isPidAlive(pid: number): boolean {
  if (!Number.isFinite(pid) || pid <= 1) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
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

function loadMergedAgyPolicy(projectRoot: string, projectName: string): OpenShellPolicy {
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

function isSshControlAlive(state: AgyChatSandboxState): boolean {
  if (!fs.existsSync(state.sshConfigPath) || !fs.existsSync(state.sshControlPath)) {
    return false;
  }
  try {
    execFileSync(
      'ssh',
      ['-S', state.sshControlPath, '-F', state.sshConfigPath, '-O', 'check', state.sshHost],
      { stdio: ['ignore', 'ignore', 'ignore'], timeout: 2000 }
    );
    return true;
  } catch {
    return false;
  }
}

function syncHostDeltaToSandbox(state: AgyChatSandboxState, sessionDir: string): void {
  const stampFile = path.join(sessionDir, 'host-sync.stamp');
  if (!fs.existsSync(stampFile)) {
    fs.writeFileSync(stampFile, '');
    return;
  }
  try {
    const findOut = execFileSync(
      'find',
      [
        '.',
        '(',
        '-name', '.git',
        '-o', '-name', 'node_modules',
        '-o', '-name', '.next',
        '-o', '-name', 'target',
        ')',
        '-prune',
        '-o',
        '-type', 'f',
        '-newer', stampFile,
        '-print',
      ],
      {
        cwd: state.projectRoot,
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
        timeout: 4000,
      }
    ).trim();

    if (!findOut) return;
    const files = findOut.split(/\r?\n/).filter(Boolean);
    if (files.length === 0) return;

    const listFile = path.join(sessionDir, `host-delta-${process.pid}.list`);
    fs.writeFileSync(listFile, files.join('\n') + '\n');
    try {
      const tarBuf = execFileSync('tar', ['-cf', '-', '-C', state.projectRoot, '-T', listFile], {
        stdio: ['ignore', 'pipe', 'ignore'],
        maxBuffer: 64 * 1024 * 1024,
        timeout: 10000,
      });
      execFileSync(
        'ssh',
        [
          '-T',
          '-S', state.sshControlPath,
          '-F', state.sshConfigPath,
          state.sshHost,
          `tar -xf - -C ${shellQuote(state.containerRoot)} && touch /tmp/.orca_sync_marker`,
        ],
        {
          input: tarBuf,
          stdio: ['pipe', 'ignore', 'ignore'],
          timeout: 10000,
        }
      );
      const now = new Date();
      fs.utimesSync(stampFile, now, now);
    } finally {
      try { fs.unlinkSync(listFile); } catch {}
    }
  } catch (err) {
    logDebug(`Antigravity host->sandbox delta sync warning: ${err}`);
  }
}

function syncSandboxDeltaToHost(state: AgyChatSandboxState, sessionDir: string): void {
  const stampFile = path.join(sessionDir, 'host-sync.stamp');
  try {
    const remoteScript = [
      `cd ${shellQuote(state.containerRoot)} || exit 0`,
      `if [ ! -f /tmp/.orca_sync_marker ]; then touch /tmp/.orca_sync_marker; exit 0; fi`,
      `find . \\( -name node_modules -o -name .next -o -name target \\) -prune -o -type f -newer /tmp/.orca_sync_marker -print > /tmp/.orca_changed_files`,
      `touch /tmp/.orca_sync_marker`,
      `if [ -s /tmp/.orca_changed_files ]; then tar -cf - -T /tmp/.orca_changed_files; fi`,
      `rm -f /tmp/.orca_changed_files`,
    ].join('; ');

    const tarOut = execFileSync(
      'ssh',
      ['-T', '-S', state.sshControlPath, '-F', state.sshConfigPath, state.sshHost, remoteScript],
      {
        stdio: ['ignore', 'pipe', 'ignore'],
        maxBuffer: 64 * 1024 * 1024,
        timeout: 15000,
      }
    );

    if (tarOut && tarOut.length > 0) {
      execFileSync('tar', ['-xf', '-', '-C', state.projectRoot], {
        input: tarOut,
        stdio: ['pipe', 'ignore', 'ignore'],
        timeout: 10000,
      });
      const now = new Date();
      if (fs.existsSync(stampFile)) {
        fs.utimesSync(stampFile, now, now);
      } else {
        fs.writeFileSync(stampFile, '');
      }
    }
  } catch (err) {
    logDebug(`Antigravity sandbox->host delta sync warning: ${err}`);
  }
}

export async function runAgyChatDaemon(
  sessionDir: string,
  projectRoot: string,
  harnessPid: number
): Promise<number> {
  process.env.AG_SANDBOX_HOST_INTERNAL = '1';
  delete process.env.ANTIGRAVITY_HARNESS_PATH;

  fs.mkdirSync(sessionDir, { recursive: true, mode: 0o700 });
  const lockPath = path.join(sessionDir, 'creating.lock');
  const statePath = path.join(sessionDir, 'state.json');

  if (fs.existsSync(lockPath)) {
    try {
      const existingPid = Number(fs.readFileSync(lockPath, 'utf8').trim());
      if (isPidAlive(existingPid)) {
        return 0;
      }
    } catch {}
    try { fs.unlinkSync(lockPath); } catch {}
  }

  fs.writeFileSync(lockPath, String(process.pid), { mode: 0o600 });

  const resolvedRoot = detectProjectRoot(projectRoot);
  const projectName = path.basename(resolvedRoot);
  const containerRoot = `/sandbox/${projectName}`;
  const sandboxName = generateSandboxName('ag', projectName, harnessPid || process.pid);
  const stageDir = fs.mkdtempSync(path.join(os.tmpdir(), `agy-chat-stage-${process.pid}-`));

  let sandbox: OpenShellSandbox | null = null;
  const sshConfigPath = path.join(sessionDir, 'ssh_config');
  const sshControlPath = path.join(sessionDir, 'ctl.sock');
  let sshHost = `openshell-${sandboxName}`;

  try {
    fs.writeFileSync(path.join(stageDir, '.gitconfig'), '[safe]\n\tdirectory = *\n');
    const uploads = [
      { source: path.join(stageDir, '.gitconfig'), destination: '/sandbox/.gitconfig' },
      { source: resolvedRoot, destination: '/sandbox' },
    ];
    const policy = loadMergedAgyPolicy(resolvedRoot, projectName);
    const providers = getExtraProviderNames();

    logDebug(`Creating Antigravity Chat Mode sandbox ${sandboxName} for ${resolvedRoot}`);
    sandbox = OpenShellSandbox.create(
      sandboxName,
      'openshell-antigravity:latest',
      providers,
      policy,
      uploads
    );

    const sshConfigRaw = execFileSync('openshell', ['sandbox', 'ssh-config', sandboxName], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 10000,
    });
    fs.writeFileSync(sshConfigPath, sshConfigRaw, { mode: 0o600 });
    const hostMatch = sshConfigRaw.match(/^\s*Host\s+(\S+)/m);
    if (hostMatch) sshHost = hostMatch[1];

    execFileSync(
      'ssh',
      [
        '-M',
        '-N',
        '-f',
        '-o', 'ControlPersist=yes',
        '-o', 'ServerAliveInterval=30',
        '-S', sshControlPath,
        '-F', sshConfigPath,
        sshHost,
      ],
      { stdio: ['ignore', 'ignore', 'ignore'], timeout: 15000 }
    );

    execFileSync(
      'ssh',
      [
        '-T',
        '-S', sshControlPath,
        '-F', sshConfigPath,
        sshHost,
        'touch /tmp/.orca_sync_marker',
      ],
      { stdio: ['ignore', 'ignore', 'ignore'], timeout: 10000 }
    );

    fs.writeFileSync(path.join(sessionDir, 'host-sync.stamp'), '');

    const state: AgyChatSandboxState = {
      sandboxName,
      projectRoot: resolvedRoot,
      projectName,
      containerRoot,
      sshConfigPath,
      sshControlPath,
      sshHost,
      harnessPid,
      daemonPid: process.pid,
      createdAt: new Date().toISOString(),
      ready: true,
    };

    const tmpStatePath = `${statePath}.tmp`;
    fs.writeFileSync(tmpStatePath, JSON.stringify(state, null, 2), { mode: 0o600 });
    fs.renameSync(tmpStatePath, statePath);
  } catch (err) {
    logDebug(`Failed to start Antigravity Chat Mode sandbox ${sandboxName}: ${err}`);
    if (sandbox) sandbox.delete();
    else new OpenShellSandbox(sandboxName).delete();
    try { fs.unlinkSync(lockPath); } catch {}
    try { fs.rmSync(stageDir, { recursive: true, force: true }); } catch {}
    return 1;
  } finally {
    try { fs.unlinkSync(lockPath); } catch {}
    try { fs.rmSync(stageDir, { recursive: true, force: true }); } catch {}
  }

  let shuttingDown = false;
  const cleanup = () => {
    if (shuttingDown) return;
    shuttingDown = true;
    try {
      if (fs.existsSync(statePath)) {
        const state = JSON.parse(fs.readFileSync(statePath, 'utf8')) as AgyChatSandboxState;
        syncSandboxDeltaToHost(state, sessionDir);
      }
    } catch {}
    try {
      execFileSync(
        'ssh',
        ['-S', sshControlPath, '-F', sshConfigPath, '-O', 'exit', sshHost],
        { stdio: ['ignore', 'ignore', 'ignore'], timeout: 3000 }
      );
    } catch {}
    sandbox?.delete();
    try { fs.rmSync(sessionDir, { recursive: true, force: true }); } catch {}
  };

  for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP'] as const) {
    process.on(sig, () => {
      cleanup();
      process.exit(0);
    });
  }

  await new Promise<void>((resolve) => {
    const timer = setInterval(() => {
      if (harnessPid > 1 && !isPidAlive(harnessPid)) {
        clearInterval(timer);
        cleanup();
        resolve();
      }
    }, 1000);
  });

  return 0;
}

function ensureAgySandboxReady(
  sessionDir: string,
  projectRoot: string,
  harnessPid: number
): AgyChatSandboxState {
  const statePath = path.join(sessionDir, 'state.json');
  const lockPath = path.join(sessionDir, 'creating.lock');

  const readValidState = (): AgyChatSandboxState | null => {
    if (!fs.existsSync(statePath)) return null;
    try {
      const state = JSON.parse(fs.readFileSync(statePath, 'utf8')) as AgyChatSandboxState;
      if (state.ready && isSshControlAlive(state)) {
        return state;
      }
    } catch {}
    return null;
  };

  const existing = readValidState();
  if (existing) return existing;

  fs.mkdirSync(sessionDir, { recursive: true, mode: 0o700 });
  let shouldSpawn = true;
  if (fs.existsSync(lockPath)) {
    try {
      const lockPid = Number(fs.readFileSync(lockPath, 'utf8').trim());
      if (isPidAlive(lockPid)) {
        shouldSpawn = false;
      }
    } catch {}
  }

  if (shouldSpawn) {
    const agentBoxBin = path.join(USER_HOME, '.local', 'bin', 'agent-box');
    const child = spawn(
      agentBoxBin,
      ['agy-chat-daemon', sessionDir, projectRoot, String(harnessPid)],
      {
        detached: true,
        stdio: 'ignore',
        env: {
          ...process.env,
          AG_SANDBOX_HOST_INTERNAL: '1',
        },
      }
    );
    child.unref();
  }

  const deadline = Date.now() + 60000;
  while (Date.now() < deadline) {
    const readyState = readValidState();
    if (readyState) return readyState;
    execFileSync('sleep', ['0.15']);
  }

  throw new Error('Timed out waiting for Antigravity OpenShell sandbox to become ready.');
}

export function getAgySessionDir(sessionKey: string): string {
  const safeSessionKey = sessionKey.replace(/[^a-zA-Z0-9_.-]/g, '_');
  const uid = typeof process.getuid === 'function' ? process.getuid() : 501;
  return path.join('/tmp', `orca-ag-openshell-${uid}`, safeSessionKey);
}

export async function runAgyChatExec(shellName: string, commandLine: string): Promise<number> {
  process.env.AG_SANDBOX_HOST_INTERNAL = '1';
  delete process.env.ANTIGRAVITY_HARNESS_PATH;

  const harnessPid = Number(process.env.AG_HARNESS_PID || process.ppid);
  const rawSessionKey = process.env.ORCA_AGENT_SESSION_ID || `ag-ppid-${harnessPid}`;
  const sessionDir = getAgySessionDir(rawSessionKey);
  const hostCwd = process.cwd();
  const projectRoot = resolveAgyProjectRoot(hostCwd, harnessPid);

  const state = ensureAgySandboxReady(sessionDir, projectRoot, harnessPid);
  syncHostDeltaToSandbox(state, sessionDir);

  const { translatedCommand, containerCwd } = translateAgyCommandAndCwd(
    commandLine,
    hostCwd,
    state.projectRoot,
    state.containerRoot
  );

  const remoteScript = [
    `cd ${shellQuote(containerCwd)} 2>/dev/null || cd ${shellQuote(state.containerRoot)}`,
    `export HOME=/home/ubuntu USER=ubuntu LOGNAME=ubuntu`,
    `export TERM=dumb PAGER=cat GIT_PAGER=cat`,
    `export PATH="/sandbox/.orca-delegate/bin:/usr/local/go/bin:/home/ubuntu/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"`,
    shellName === 'zsh'
      ? `if command -v zsh >/dev/null 2>&1; then zsh -c ${shellQuote(translatedCommand)}; else bash -c ${shellQuote(translatedCommand)}; fi`
      : `bash -c ${shellQuote(translatedCommand)}`,
  ].join('\n');

  const exitCode = await new Promise<number>((resolve) => {
    const child = spawn(
      'ssh',
      ['-T', '-S', state.sshControlPath, '-F', state.sshConfigPath, state.sshHost, remoteScript],
      { stdio: 'inherit' }
    );
    child.on('close', (code, signal) => {
      resolve(code ?? (signal ? 128 + (os.constants.signals[signal] ?? 1) : 1));
    });
    child.on('error', () => resolve(1));
  });

  syncSandboxDeltaToHost(state, sessionDir);
  return exitCode;
}
