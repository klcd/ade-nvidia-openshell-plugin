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
    const providers = [...new Set(['antigravity', ...getExtraProviderNames()])];

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
        [
          'mkdir -p /sandbox/.orca-delegate/bin',
          `cat > /sandbox/.orca-delegate/bin/openshell-l7-allow <<'EOF'`,
          '#!/usr/bin/env python3',
          'import json, os, sys, time',
          'args = sys.argv[1:]',
          'req = {"scope": "session", "host": "", "port": 443, "method": "GET", "path": "/**", "binary": "*"}',
          'i = 0',
          'while i < len(args):',
          '    a = args[i]',
          '    if a in ("--scope", "--host", "--method", "--path", "--binary") and i + 1 < len(args):',
          '        req[a[2:]] = args[i + 1]; i += 2',
          '    elif a == "--port" and i + 1 < len(args):',
          '        req["port"] = int(args[i + 1]); i += 2',
          '    else:',
          '        i += 1',
          'if not req["host"]:',
          '    sys.stderr.write("Usage: openshell-l7-allow --scope <session|workspace|global> --host <domain> [--port 443] [--method GET] [--path /**]\\n")',
          '    sys.exit(1)',
          `req_dir = ${JSON.stringify(`${containerRoot}/.orca-openshell-l7-requests`)}`,
          'os.makedirs(req_dir, exist_ok=True)',
          'fname = os.path.join(req_dir, f"req-{int(time.time()*1000)}-{os.getpid()}.json")',
          'with open(fname, "w") as f:',
          '    json.dump(req, f)',
          'print(f"Queued L7 policy rule ({req[\'scope\']}): {req[\'method\']} https://{req[\'host\']}:{req[\'port\']}{req[\'path\']}")',
          'EOF',
          'chmod 755 /sandbox/.orca-delegate/bin/openshell-l7-allow',
          'touch /tmp/.orca_sync_marker',
        ].join('\n'),
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

  const checkL7RequestQueue = () => {
    const reqDir = path.join(resolvedRoot, '.orca-openshell-l7-requests');
    if (!fs.existsSync(reqDir)) return;
    try {
      const files = fs.readdirSync(reqDir).filter(f => f.endsWith('.json')).sort();
      for (const file of files) {
        const fullPath = path.join(reqDir, file);
        try {
          const req = JSON.parse(fs.readFileSync(fullPath, 'utf8')) as {
            scope?: 'session' | 'workspace' | 'global';
            host?: string;
            port?: number;
            method?: string;
            path?: string;
            binary?: string;
          };
          fs.unlinkSync(fullPath);
          if (req.host) {
            void runAgyPolicyAdd([
              '--scope', req.scope || 'session',
              '--host', req.host,
              '--port', String(req.port || 443),
              '--method', req.method || 'GET',
              '--path', req.path || '/**',
              '--binary', req.binary || '*',
              '--sandbox', sandboxName,
            ]);
          }
        } catch {
          try { fs.unlinkSync(fullPath); } catch {}
        }
      }
      if (fs.readdirSync(reqDir).length === 0) {
        try { fs.rmdirSync(reqDir); } catch {}
      }
    } catch {}
  };

  await new Promise<void>((resolve) => {
    const timer = setInterval(() => {
      checkL7RequestQueue();
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

export interface BlockedEgressInfo {
  host: string;
  port: number;
  method: string;
  path: string;
  binary: string;
}

export function detectBlockedEgress(
  commandLine: string,
  exitCode: number,
  stdoutText: string,
  stderrText: string
): BlockedEgressInfo | null {
  const combined = `${stdoutText}\n${stderrText}`;

  // 1. Check structured OpenShell L7 HTTP 403 policy denial payload
  if (combined.includes('X-OpenShell-Policy:') || combined.includes('"error":"policy_denied"')) {
    const jsonMatch = /\{"binary":[^\n]*?"rule_missing":\{[^\n]*?\}\}/.exec(combined);
    if (jsonMatch) {
      try {
        const parsed = JSON.parse(jsonMatch[0]) as {
          binary?: string;
          host?: string;
          method?: string;
          path?: string;
          port?: number;
          rule_missing?: {
            binary?: string;
            host?: string;
            method?: string;
            path?: string;
            port?: number;
          };
        };
        const rm = parsed.rule_missing || parsed;
        if (rm.host) {
          return {
            host: rm.host,
            port: Number(rm.port || 443),
            method: (rm.method || 'GET').toUpperCase(),
            path: rm.path || '/**',
            binary: rm.binary || '*',
          };
        }
      } catch {}
    }
  }

  // 2. Check non-zero exit code (or curl connection refusal) for commands targeting a URL
  const isNetworkFailure =
    exitCode !== 0 ||
    /Failed to connect|Couldn't connect to server|Connection refused|Could not resolve host|X-OpenShell-Policy:/i.test(
      combined
    );
  if (!isNetworkFailure) return null;

  const urlMatch = /(https?):\/\/([a-zA-Z0-9.-]+)(?::(\d+))?(\/[^\s"']*)?/.exec(commandLine);
  if (!urlMatch) return null;

  if (!/\b(curl|wget|fetch|http|gh|npm|bun|pip|poetry|cargo|go|python3?|node)\b/.test(commandLine)) {
    return null;
  }

  const scheme = urlMatch[1].toLowerCase();
  const host = urlMatch[2];
  const port = Number(urlMatch[3] || (scheme === 'http' ? 80 : 443));
  const rawPath = urlMatch[4] || '/**';
  const cleanPath = rawPath.split('?')[0] || '/**';
  const methodMatch = /(?:-X|--request)\s+['"]?(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)['"]?/i.exec(
    commandLine
  );
  const method = methodMatch
    ? methodMatch[1].toUpperCase()
    : /\s(?:-d|--data|--data-raw|--data-binary)\s/.test(commandLine)
      ? 'POST'
      : 'GET';

  return {
    host,
    port,
    method,
    path: cleanPath,
    binary: '*',
  };
}

function promptUserForL7Approval(
  info: BlockedEgressInfo,
  sandboxName: string
): 'session' | 'workspace' | 'global' | 'deny' {
  if (process.env.ORCA_OPENSHELL_AUTO_APPROVE_SCOPE) {
    const s = process.env.ORCA_OPENSHELL_AUTO_APPROVE_SCOPE;
    if (s === 'session' || s === 'workspace' || s === 'global' || s === 'deny') return s;
  }
  if (process.platform !== 'darwin' || process.env.ORCA_OPENSHELL_DISABLE_POPUP === '1') {
    return 'deny';
  }

  const optSession = '1. Allow for this session only (Live hot-reload)';
  const optWorkspace = '2. Allow and save for this project (.agents/policies/l7-custom.json)';
  const optGlobal = '3. Allow in general for all projects (Global policy)';
  const optDeny = '4. Keep blocked (Deny)';

  const promptText =
    `OpenShell blocked outbound network egress in sandbox ${sandboxName}:\\n\\n` +
    `  ${info.method} https://${info.host}:${info.port}${info.path}\\n\\n` +
    `Select how to handle this L7 rule:`;

  const script = [
    `set opts to {${JSON.stringify(optSession)}, ${JSON.stringify(optWorkspace)}, ${JSON.stringify(optGlobal)}, ${JSON.stringify(optDeny)}}`,
    `set choice to choose from list opts with title "OpenShell L7 Network Policy" with prompt "${promptText}" default items {${JSON.stringify(optSession)}} OK button name "Apply Rule" cancel button name "Keep Blocked"`,
    `if choice is false then return "deny"`,
    `return item 1 of choice`,
  ].join('\n');

  try {
    const out = execFileSync('osascript', ['-e', script], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 60000,
    }).trim();
    if (out.startsWith('1.')) return 'session';
    if (out.startsWith('2.')) return 'workspace';
    if (out.startsWith('3.')) return 'global';
    return 'deny';
  } catch {
    return 'deny';
  }
}

async function runRemoteSshCaptured(
  state: AgyChatSandboxState,
  remoteScript: string
): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];
    const child = spawn(
      'ssh',
      ['-T', '-S', state.sshControlPath, '-F', state.sshConfigPath, state.sshHost, remoteScript],
      { stdio: ['inherit', 'pipe', 'pipe'] }
    );
    child.stdout.on('data', (chunk: Buffer) => stdoutChunks.push(Buffer.from(chunk)));
    child.stderr.on('data', (chunk: Buffer) => stderrChunks.push(Buffer.from(chunk)));
    child.on('close', (code, signal) => {
      resolve({
        exitCode: code ?? (signal ? 128 + (os.constants.signals[signal] ?? 1) : 1),
        stdout: Buffer.concat(stdoutChunks).toString('utf8'),
        stderr: Buffer.concat(stderrChunks).toString('utf8'),
      });
    });
    child.on('error', () =>
      resolve({
        exitCode: 1,
        stdout: Buffer.concat(stdoutChunks).toString('utf8'),
        stderr: Buffer.concat(stderrChunks).toString('utf8'),
      })
    );
  });
}

export async function runAgyChatExec(shellName: string, commandLine: string): Promise<number> {
  process.env.AG_SANDBOX_HOST_INTERNAL = '1';
  delete process.env.ANTIGRAVITY_HARNESS_PATH;

  const trimmedCmd = commandLine.trim();
  if (trimmedCmd.startsWith('openshell-l7-allow ')) {
    const rawTokens = trimmedCmd
      .slice('openshell-l7-allow '.length)
      .match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g)
      ?.map(t => t.replace(/^['"]|['"]$/g, '')) || [];
    return runAgyPolicyAdd(rawTokens);
  }

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

  let result = await runRemoteSshCaptured(state, remoteScript);
  const blocked = detectBlockedEgress(commandLine, result.exitCode, result.stdout, result.stderr);

  if (blocked) {
    const decision = promptUserForL7Approval(blocked, state.sandboxName);
    if (decision !== 'deny') {
      await runAgyPolicyAdd([
        '--scope', decision,
        '--host', blocked.host,
        '--port', String(blocked.port),
        '--method', blocked.method,
        '--path', blocked.path,
        '--binary', blocked.binary || '*',
        '--sandbox', state.sandboxName,
      ]);

      // Wait for OpenShell supervisor settings poll (~1s interval) and automatically retry
      for (let attempt = 0; attempt < 5; attempt++) {
        execFileSync('sleep', ['0.7']);
        result = await runRemoteSshCaptured(state, remoteScript);
        const stillBlocked = detectBlockedEgress(
          commandLine,
          result.exitCode,
          result.stdout,
          result.stderr
        );
        if (!stillBlocked) break;
      }
    } else {
      if (result.stdout) process.stdout.write(result.stdout);
      if (result.stderr) process.stderr.write(result.stderr);
      process.stderr.write(
        `\n[OpenShell Egress Denied by User] Target: ${blocked.method} https://${blocked.host}:${blocked.port}${blocked.path} (sandbox: ${state.sandboxName})\n`
      );
      syncSandboxDeltaToHost(state, sessionDir);
      return result.exitCode !== 0 ? result.exitCode : 1;
    }
  }

  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);
  const exitCode = result.exitCode;

  syncSandboxDeltaToHost(state, sessionDir);

  const reqDir = path.join(state.projectRoot, '.orca-openshell-l7-requests');
  if (fs.existsSync(reqDir)) {
    try {
      const files = fs.readdirSync(reqDir).filter(f => f.endsWith('.json')).sort();
      for (const file of files) {
        const fullPath = path.join(reqDir, file);
        try {
          const req = JSON.parse(fs.readFileSync(fullPath, 'utf8')) as {
            scope?: 'session' | 'workspace' | 'global';
            host?: string;
            port?: number;
            method?: string;
            path?: string;
            binary?: string;
          };
          fs.unlinkSync(fullPath);
          if (req.host) {
            await runAgyPolicyAdd([
              '--scope', req.scope || 'session',
              '--host', req.host,
              '--port', String(req.port || 443),
              '--method', req.method || 'GET',
              '--path', req.path || '/**',
              '--binary', req.binary || '*',
              '--sandbox', state.sandboxName,
            ]);
          }
        } catch {
          try { fs.unlinkSync(fullPath); } catch {}
        }
      }
      if (fs.readdirSync(reqDir).length === 0) {
        try { fs.rmdirSync(reqDir); } catch {}
      }
    } catch {}
  }

  return exitCode;
}

export async function runAgyPolicyAdd(rawArgs: string[]): Promise<number> {
  process.env.AG_SANDBOX_HOST_INTERNAL = '1';
  delete process.env.ANTIGRAVITY_HARNESS_PATH;

  let scope: 'session' | 'workspace' | 'global' = 'session';
  let host = '';
  let port = 443;
  let method = 'GET';
  let urlPath = '/**';
  let binary = '*';
  let sandboxName = '';
  let agent = 'antigravity';

  for (let i = 0; i < rawArgs.length; i++) {
    const arg = rawArgs[i];
    if (arg === '--scope' && rawArgs[i + 1]) scope = rawArgs[++i] as any;
    else if (arg === '--host' && rawArgs[i + 1]) host = rawArgs[++i];
    else if (arg === '--port' && rawArgs[i + 1]) port = Number(rawArgs[++i]) || 443;
    else if (arg === '--method' && rawArgs[i + 1]) method = rawArgs[++i].toUpperCase();
    else if (arg === '--path' && rawArgs[i + 1]) urlPath = rawArgs[++i];
    else if (arg === '--binary' && rawArgs[i + 1]) binary = rawArgs[++i];
    else if (arg === '--sandbox' && rawArgs[i + 1]) sandboxName = rawArgs[++i];
    else if (arg === '--agent' && rawArgs[i + 1]) agent = rawArgs[++i];
  }

  if (!host) {
    console.error('Usage: agent-box policy-add --scope <session|workspace|global> --host <domain> [--port 443] [--method GET] [--path "/**"]');
    return 1;
  }

  const normalizedPath = urlPath.startsWith('/') ? urlPath : `/${urlPath}`;
  const ruleName = `${host.replace(/[^a-zA-Z0-9]+/g, '_')}_l7`;
  const effectiveBinaries =
    binary === '*'
      ? ['/usr/bin/curl', '/usr/bin/git', '/usr/local/bin/node', '/usr/bin/python3', '/usr/bin/gh']
      : [binary];
  const projectRoot = resolveAgyProjectRoot(process.cwd(), process.ppid);

  if (scope === 'workspace' || scope === 'global') {
    const targetFile =
      scope === 'workspace'
        ? path.join(projectRoot, '.agents', 'policies', 'l7-custom.json')
        : path.join(USER_HOME, '.agents', 'orca-openshell-policies', `${agent}.json`);
    fs.mkdirSync(path.dirname(targetFile), { recursive: true });
    let doc: Record<string, any> = { version: 1, network_policies: {} };
    if (fs.existsSync(targetFile)) {
      try { doc = JSON.parse(fs.readFileSync(targetFile, 'utf8')); } catch {}
    }
    doc.version ??= 1;
    doc.network_policies ??= {};
    const existingPol = doc.network_policies[ruleName] || {
      name: ruleName,
      binaries: effectiveBinaries.map(p => ({ path: p })),
      endpoints: [],
    };
    const bins: Array<{ path: string }> = Array.isArray(existingPol.binaries) ? existingPol.binaries : [];
    for (const b of effectiveBinaries) {
      if (!bins.some(item => item?.path === b)) bins.push({ path: b });
    }
    existingPol.binaries = bins;

    const endpoints: any[] = Array.isArray(existingPol.endpoints) ? existingPol.endpoints : [];
    let ep = endpoints.find(e => e?.host === host && Number(e?.port || 443) === port);
    if (!ep) {
      ep = { host, port, protocol: 'rest', enforcement: 'enforce' };
      endpoints.push(ep);
    }
    delete ep.access;
    ep.rules = Array.isArray(ep.rules) ? ep.rules : [];
    if (!ep.rules.some((r: any) => r?.allow?.method === method && r?.allow?.path === normalizedPath)) {
      ep.rules.push({ allow: { method, path: normalizedPath } });
    }
    existingPol.endpoints = endpoints;
    doc.network_policies[ruleName] = existingPol;
    fs.writeFileSync(targetFile, JSON.stringify(doc, null, 2) + '\n', 'utf8');
    console.log(`Saved persistent L7 rule (${scope}) to ${targetFile}`);
  }

  const targetSandboxes: string[] = [];
  if (sandboxName) {
    targetSandboxes.push(sandboxName);
  } else {
    try {
      const out = execFileSync('openshell', ['sandbox', 'list'], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
      });
      for (const line of out.split(/\r?\n/)) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('NAME') || trimmed.startsWith('No sandboxes')) continue;
        const parts = trimmed.split(/\s+/);
        const name = parts[0];
        const phase = parts[parts.length - 1] || '';
        if (name && phase.toLowerCase() === 'ready') {
          targetSandboxes.push(name);
        }
      }
    } catch {}
  }

  const binFlags = effectiveBinaries.flatMap(b => ['--binary', b]);
  for (const sb of targetSandboxes) {
    try {
      execFileSync(
        'openshell',
        [
          'policy', 'update', sb,
          '--rule-name', ruleName,
          ...binFlags,
          '--add-endpoint', `${host}:${port}:read-write:rest:enforce`,
        ],
        { stdio: ['ignore', 'pipe', 'pipe'], timeout: 10000 }
      );
      execFileSync(
        'openshell',
        [
          'policy', 'update', sb,
          '--rule-name', ruleName,
          ...binFlags,
          '--add-allow', `${host}:${port}:${method}:${normalizedPath}`,
        ],
        { stdio: ['ignore', 'pipe', 'pipe'], timeout: 10000 }
      );
      console.log(`Live-applied L7 rule (${method} https://${host}:${port}${normalizedPath}) to sandbox ${sb}`);
    } catch (err) {
      console.error(`Failed to update sandbox ${sb}: ${err}`);
      return 1;
    }
  }

  return 0;
}

