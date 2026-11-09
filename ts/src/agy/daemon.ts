import { execFileSync, spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pruneSandboxSessionEgress } from '../../../orca-plugin/src/state/session-egress.ts';
import {
  detectProjectRoot,
  generateSandboxName,
  getSandboxIdleTimeoutSeconds,
  logDebug,
  registerSandboxSession,
  unregisterSandboxSession,
  USER_HOME,
} from '../config.js';
import {
  ensureValidHostTmpDir,
  OpenShellSandbox,
  spawnSandboxLifecycleWatchdog,
} from '../sandbox.js';
import { getExtraProviderNames } from '../sandbox-scope.js';
import { drainL7RequestQueue } from './egress.js';
import {
  getAgySessionDir,
  hasActiveAgyExecs,
  isPidAlive,
  loadMergedAgyPolicy,
  readLastAgyActivity,
  touchAgyActivity,
  writeAtomicState,
  type AgyChatSandboxState,
} from './state.js';
import { isSshControlAlive, syncSandboxDeltaToHost } from './sync.js';

export async function runAgyChatDaemon(
  sessionDirOrKey: string,
  projectRoot: string,
  harnessPid: number
): Promise<number> {
  process.env.AG_SANDBOX_HOST_INTERNAL = '1';
  delete process.env.ANTIGRAVITY_HARNESS_PATH;
  ensureValidHostTmpDir();

  const rawSessionKey = path.isAbsolute(sessionDirOrKey)
    ? ''
    : sessionDirOrKey || process.env.ORCA_AGENT_SESSION_ID || `ag-ppid-${harnessPid}`;
  const sessionDir = path.isAbsolute(sessionDirOrKey)
    ? sessionDirOrKey
    : getAgySessionDir(rawSessionKey);
  const sessionBase = path.basename(sessionDir);
  const resolvedAgentSessionId =
    process.env.ORCA_AGENT_SESSION_ID ||
    (rawSessionKey.startsWith('antigravity_') ? rawSessionKey : undefined) ||
    (sessionBase.startsWith('antigravity_') ? sessionBase : undefined);

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
    try {
      fs.unlinkSync(lockPath);
    } catch {}
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
          `req = {"scope": "session", "sandboxName": ${JSON.stringify(sandboxName)}, "host": "", "port": 443, "method": "GET", "path": "/**", "binary": "*"}`,
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

    touchAgyActivity(sessionDir);

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
      ...(resolvedAgentSessionId ? { agentSessionId: resolvedAgentSessionId } : {}),
      createdAt: new Date().toISOString(),
      ready: true,
      hibernated: false,
    };

    writeAtomicState(statePath, state);
    registerSandboxSession({
      sandboxName,
      agent: 'antigravity',
      workspacePath: resolvedRoot,
      agentSessionId: resolvedAgentSessionId,
      pid: process.pid,
    });
  } catch (err) {
    logDebug(`Failed to start Antigravity Chat Mode sandbox ${sandboxName}: ${err}`);
    if (sandbox) sandbox.delete();
    else new OpenShellSandbox(sandboxName).delete();
    try {
      fs.unlinkSync(lockPath);
    } catch {}
    try {
      fs.rmSync(stageDir, { recursive: true, force: true });
    } catch {}
    return 1;
  } finally {
    try {
      fs.unlinkSync(lockPath);
    } catch {}
    try {
      fs.rmSync(stageDir, { recursive: true, force: true });
    } catch {}
  }

  const watchdogPid = spawnSandboxLifecycleWatchdog(process.pid, sandboxName);

  let shuttingDown = false;
  const cleanup = (alreadyDeleted = false) => {
    if (shuttingDown) return;
    shuttingDown = true;
    unregisterSandboxSession(sandboxName);
    let currentState: AgyChatSandboxState | null = null;
    try {
      if (fs.existsSync(statePath)) {
        currentState = JSON.parse(fs.readFileSync(statePath, 'utf8')) as AgyChatSandboxState;
      }
    } catch {}
    if (!alreadyDeleted && currentState && !currentState.hibernated) {
      try {
        syncSandboxDeltaToHost(currentState, sessionDir);
      } catch {}
      try {
        execFileSync(
          'ssh',
          ['-S', sshControlPath, '-F', sshConfigPath, '-O', 'exit', currentState.sshHost || sshHost],
          { stdio: ['ignore', 'ignore', 'ignore'], timeout: 3000 }
        );
      } catch {}
    }
    if (!alreadyDeleted) {
      sandbox?.delete();
    }
    if (watchdogPid) {
      try {
        process.kill(watchdogPid, 'SIGTERM');
      } catch {}
    }
    try {
      pruneSandboxSessionEgress(sandboxName, USER_HOME);
    } catch {}
    try {
      fs.rmSync(sessionDir, { recursive: true, force: true });
    } catch {}
  };

  for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP'] as const) {
    process.on(sig, () => {
      cleanup();
      process.exit(0);
    });
  }
  process.once('exit', () => {
    if (!shuttingDown) {
      unregisterSandboxSession(sandboxName);
      sandbox?.delete(true);
    }
  });

  const hibernateLockPath = path.join(sessionDir, 'hibernating.lock');
  const wakeLockPath = path.join(sessionDir, 'waking.lock');

  const tryIdleHibernate = (): 'ok' | 'deleted' => {
    if (shuttingDown || !sandbox) return 'ok';
    const idleTimeoutSec = getSandboxIdleTimeoutSeconds(USER_HOME, {
      sandboxName,
      agentSessionId: resolvedAgentSessionId,
    });
    if (idleTimeoutSec <= 0) return 'ok';

    let currentState: AgyChatSandboxState | null = null;
    try {
      if (fs.existsSync(statePath)) {
        currentState = JSON.parse(fs.readFileSync(statePath, 'utf8')) as AgyChatSandboxState;
      }
    } catch {}
    if (!currentState || !currentState.ready || currentState.hibernated) return 'ok';
    if (hasActiveAgyExecs(sessionDir)) return 'ok';
    if (fs.existsSync(wakeLockPath)) {
      try {
        const wakePid = Number(fs.readFileSync(wakeLockPath, 'utf8').trim());
        if (isPidAlive(wakePid)) return 'ok';
      } catch {}
    }

    const lastActivity = readLastAgyActivity(sessionDir);
    if (!lastActivity || Date.now() - lastActivity < idleTimeoutSec * 1000) return 'ok';

    try {
      fs.writeFileSync(hibernateLockPath, String(process.pid), { mode: 0o600 });
      if (
        hasActiveAgyExecs(sessionDir) ||
        Date.now() - readLastAgyActivity(sessionDir) < idleTimeoutSec * 1000
      ) {
        return 'ok';
      }
      logDebug(
        `Idle timeout (${idleTimeoutSec}s) reached for Antigravity sandbox ${sandboxName}; stopping container`
      );
      try {
        syncSandboxDeltaToHost(currentState, sessionDir);
      } catch {}
      try {
        execFileSync(
          'ssh',
          [
            '-S', currentState.sshControlPath,
            '-F', currentState.sshConfigPath,
            '-O', 'exit',
            currentState.sshHost,
          ],
          { stdio: ['ignore', 'ignore', 'ignore'], timeout: 3000 }
        );
      } catch {}
      if (sandbox.stop()) {
        writeAtomicState(statePath, { ...currentState, hibernated: true });
      } else {
        const phase = sandbox.getPhase();
        if (phase === null) {
          logDebug(`Sandbox ${sandboxName} was deleted externally; exiting Antigravity daemon`);
          return 'deleted';
        }
        if (phase === 'Stopped') {
          writeAtomicState(statePath, { ...currentState, hibernated: true });
        }
      }
    } finally {
      try {
        fs.unlinkSync(hibernateLockPath);
      } catch {}
    }
    return 'ok';
  };

  await new Promise<void>(resolve => {
    let ticks = 0;
    const timer = setInterval(() => {
      ticks++;
      let hibernatedNow = false;
      try {
        if (fs.existsSync(statePath)) {
          const st = JSON.parse(fs.readFileSync(statePath, 'utf8')) as AgyChatSandboxState;
          hibernatedNow = Boolean(st.hibernated);
        }
      } catch {}
      if (!hibernatedNow) {
        void drainL7RequestQueue(resolvedRoot, sandboxName);
      }
      if (harnessPid > 1 && !isPidAlive(harnessPid)) {
        clearInterval(timer);
        cleanup();
        resolve();
        return;
      }
      if (tryIdleHibernate() === 'deleted') {
        clearInterval(timer);
        cleanup(true);
        resolve();
        return;
      }
      if (ticks % 10 === 0 && (!fs.existsSync(statePath) || sandbox?.getPhase() === null)) {
        logDebug(
          `Sandbox ${sandboxName} or session state removed externally; exiting Antigravity daemon`
        );
        clearInterval(timer);
        cleanup(true);
        resolve();
        return;
      }
    }, 1000);
  });

  return 0;
}

export function wakeHibernatedAgySandbox(
  sessionDir: string,
  statePath: string,
  state: AgyChatSandboxState
): AgyChatSandboxState | 'deleted' | null {
  const wakeLockPath = path.join(sessionDir, 'waking.lock');
  if (fs.existsSync(wakeLockPath)) {
    try {
      const existingWakePid = Number(fs.readFileSync(wakeLockPath, 'utf8').trim());
      if (isPidAlive(existingWakePid)) {
        return null; // Another process is currently waking this sandbox
      }
    } catch {}
  }

  fs.writeFileSync(wakeLockPath, String(process.pid), { mode: 0o600 });
  try {
    touchAgyActivity(sessionDir);
    const sb = new OpenShellSandbox(state.sandboxName);
    const phase = sb.getPhase();
    if (phase === null) {
      logDebug(`Sandbox ${state.sandboxName} was deleted externally; recreating clean session`);
      if (isPidAlive(state.daemonPid)) {
        try {
          process.kill(state.daemonPid, 'SIGTERM');
        } catch {}
      }
      try {
        fs.unlinkSync(statePath);
      } catch {}
      return 'deleted';
    }

    if (phase !== 'Ready') {
      logDebug(`Waking stopped Antigravity sandbox ${state.sandboxName} (phase=${phase})`);
      if (!sb.start()) {
        throw new Error(`Failed to restart OpenShell sandbox ${state.sandboxName}`);
      }
    }

    let sshHost = state.sshHost;
    try {
      const sshConfigRaw = execFileSync('openshell', ['sandbox', 'ssh-config', state.sandboxName], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
        timeout: 10000,
      });
      fs.writeFileSync(state.sshConfigPath, sshConfigRaw, { mode: 0o600 });
      const hostMatch = sshConfigRaw.match(/^\s*Host\s+(\S+)/m);
      if (hostMatch) sshHost = hostMatch[1];
    } catch {}

    try {
      fs.unlinkSync(state.sshControlPath);
    } catch {}
    execFileSync(
      'ssh',
      [
        '-M',
        '-N',
        '-f',
        '-o', 'ControlPersist=yes',
        '-o', 'ServerAliveInterval=30',
        '-S', state.sshControlPath,
        '-F', state.sshConfigPath,
        sshHost,
      ],
      { stdio: ['ignore', 'ignore', 'ignore'], timeout: 15000 }
    );

    try {
      execFileSync(
        'ssh',
        [
          '-T',
          '-S', state.sshControlPath,
          '-F', state.sshConfigPath,
          sshHost,
          'test -f /tmp/.orca_sync_marker || touch /tmp/.orca_sync_marker',
        ],
        { stdio: ['ignore', 'ignore', 'ignore'], timeout: 8000 }
      );
    } catch {}

    const updatedState: AgyChatSandboxState = {
      ...state,
      sshHost,
      ready: true,
      hibernated: false,
    };
    writeAtomicState(statePath, updatedState);
    touchAgyActivity(sessionDir);
    return updatedState;
  } finally {
    try {
      fs.unlinkSync(wakeLockPath);
    } catch {}
  }
}

export function ensureAgySandboxReady(
  sessionDir: string,
  projectRoot: string,
  harnessPid: number
): AgyChatSandboxState {
  const statePath = path.join(sessionDir, 'state.json');
  const lockPath = path.join(sessionDir, 'creating.lock');
  const hibernateLockPath = path.join(sessionDir, 'hibernating.lock');

  fs.mkdirSync(sessionDir, { recursive: true, mode: 0o700 });
  touchAgyActivity(sessionDir);

  const waitDeadline = Date.now() + 30000;
  while (fs.existsSync(hibernateLockPath) && Date.now() < waitDeadline) {
    try {
      const hPid = Number(fs.readFileSync(hibernateLockPath, 'utf8').trim());
      if (!isPidAlive(hPid)) break;
    } catch {
      break;
    }
    execFileSync('sleep', ['0.15']);
  }

  const readStateRaw = (): AgyChatSandboxState | null => {
    if (!fs.existsSync(statePath)) return null;
    try {
      return JSON.parse(fs.readFileSync(statePath, 'utf8')) as AgyChatSandboxState;
    } catch {
      return null;
    }
  };

  const existingRaw = readStateRaw();
  if (existingRaw?.ready) {
    if (!existingRaw.hibernated && isSshControlAlive(existingRaw)) {
      return existingRaw;
    }
    if (isPidAlive(existingRaw.daemonPid)) {
      const woken = wakeHibernatedAgySandbox(sessionDir, statePath, existingRaw);
      if (woken && woken !== 'deleted') {
        return woken;
      }
      if (woken === null) {
        const wakeWaitDeadline = Date.now() + 60000;
        while (Date.now() < wakeWaitDeadline) {
          const st = readStateRaw();
          if (st?.ready && !st.hibernated && isSshControlAlive(st)) {
            return st;
          }
          execFileSync('sleep', ['0.15']);
        }
      }
    }
  }

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
          TMPDIR: '/tmp',
        },
      }
    );
    child.unref();
  }

  const deadline = Date.now() + 60000;
  while (Date.now() < deadline) {
    const st = readStateRaw();
    if (st?.ready && !st.hibernated && isSshControlAlive(st)) return st;
    execFileSync('sleep', ['0.15']);
  }

  throw new Error('Timed out waiting for Antigravity OpenShell sandbox to become ready.');
}
