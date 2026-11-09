import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, execFileSync } from 'node:child_process';
import type { AgentAdapter, OpenShellPolicy } from './types.js';
import {
  detectProjectRoot,
  generateSandboxName,
  getSandboxIdleTimeoutSeconds,
  findHostBinary,
  isSandboxModeEnabled,
  logDebug,
  registerSandboxSession,
  unregisterSandboxSession,
} from './config.js';
import { discoverAndMergePolicies, mergePolicies, mergeTwoPolicies, parsePolicyFile } from './policy.js';
import { OpenShellSandbox } from './sandbox.js';
import { assertNoCredentialLeak, redactCredentialFiles } from './credential-security.js';
import { isTurnCompleteFrame, rewriteJsonRpcPaths } from './protocols/jsonrpc.js';
import { StreamSessionTracker } from './protocols/session-hibernation.js';
import { applyWorkspaceWriteScope, getExtraProviderNames, getWorkspaceWritePaths } from './sandbox-scope.js';
import { DelegationBroker, recordLaunch, forgetLaunch, revokeGrant, readGrant, writeGrant } from './delegation.js';
import { CodexAdapter } from './agents/codex.js';
import { ClaudeAdapter } from './agents/claude.js';
import { mergeWorkspace, snapshotWorkspace } from './workspace-merge.js';

function resolveOrcaWorkspaceId(projectRoot: string): string {
  if (process.env.OPENSHELL_BRIDGE_WORKSPACE_ID) return process.env.OPENSHELL_BRIDGE_WORKSPACE_ID;
  if (process.env.ORCA_STRUCTURED_SESSION !== '1') return '';
  try {
    const out = execFileSync('orca', ['worktree', 'list', '--json'], {
      encoding: 'utf8',
      timeout: 5000,
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    const parsed = JSON.parse(out) as { result?: { worktrees?: Array<{ id?: string; path?: string }> } };
    const match = parsed.result?.worktrees?.find(w => w.path === projectRoot);
    return match?.id || '';
  } catch {
    return '';
  }
}

async function runHostPassthrough(binaryName: string, rawArgs: string[]): Promise<number> {
  const hostBin = findHostBinary(binaryName);
  if (!hostBin) {
    console.error(`Native host binary "${binaryName}" not found on PATH while OpenShell sandboxing is disabled.`);
    return 1;
  }
  const cleanEnv = Object.fromEntries(
    Object.entries(process.env).filter(
      ([key]) => !key.startsWith('OPENSHELL_BRIDGE_') && key !== 'OPENSHELL_SANDBOX_DISABLED'
    )
  );
  logDebug(`Sandbox mode disabled — launching native host binary: ${hostBin} ${rawArgs.join(' ')}`);
  return new Promise<number>((resolve) => {
    const child = spawn(hostBin, rawArgs, {
      stdio: 'inherit',
      env: cleanEnv,
    });
    const forwardSignal = (sig: NodeJS.Signals) => {
      if (!child.killed) {
        try { child.kill(sig); } catch {}
      }
    };
    process.on('SIGINT', forwardSignal);
    process.on('SIGTERM', forwardSignal);
    process.on('SIGHUP', forwardSignal);
    child.on('close', (code, signal) => {
      process.off('SIGINT', forwardSignal);
      process.off('SIGTERM', forwardSignal);
      process.off('SIGHUP', forwardSignal);
      resolve(code ?? (signal ? 128 + (os.constants.signals[signal] ?? 1) : 0));
    });
    child.on('error', (err) => {
      console.error(`Failed to launch host binary ${hostBin}:`, err);
      resolve(1);
    });
  });
}

export async function runSandboxSession(agent: AgentAdapter, rawArgs: string[]): Promise<number> {
  const cwd = process.cwd();

  // 1. Check for fast-path bypass (e.g. --version / discovery probes)
  if (agent.shouldBypassSandbox(rawArgs, cwd)) {
    const hostBin = findHostBinary(agent.binaryName);
    if (hostBin) {
      logDebug(`Bypassing sandbox for fast-path command: ${hostBin} ${rawArgs.join(' ')}`);
      try {
        execFileSync(hostBin, rawArgs, { stdio: 'inherit' });
        return 0;
      } catch (err: unknown) {
        return (err as { status?: number }).status ?? 1;
      }
    }
  }

  // 2. Discover workspace and check per-worktree (+ child workspace) sandbox toggle
  const projectRoot = detectProjectRoot(cwd);
  if (!isSandboxModeEnabled(undefined, projectRoot, process.env.OPENSHELL_BRIDGE_WORKSPACE_ID)) {
    return runHostPassthrough(agent.binaryName, rawArgs);
  }
  const projectName = path.basename(projectRoot);
  const workspaceWritePaths = getWorkspaceWritePaths(projectRoot);
  const structuredSession = process.env.ORCA_STRUCTURED_SESSION === '1';
  const orcaSession =
    process.env.OPENSHELL_BRIDGE_REQUIRED === '1' ||
    process.env.ORCA_OPENSHELL_REQUIRED === '1' ||
    structuredSession;
  let baseline = orcaSession ? snapshotWorkspace(projectRoot) : null;
  const prefixMap: Record<string, string> = { claude: 'cc', codex: 'cx', agy: 'ag' };
  const prefix = prefixMap[agent.type] || 'sb';
  const sandboxName = generateSandboxName(prefix, projectName);

  logDebug(`Starting ${agent.type} session for ${projectName} (sandbox: ${sandboxName}, structured: ${structuredSession})`);

  // 3. Discover and merge policies
  const defaultOrcaPolicy = path.join(os.homedir(), '.orca', 'plugins', 'openshell-bridge', 'policies', 'orca-standard.yaml');
  const explicitPolicy =
    process.env.OPENSHELL_BRIDGE_POLICY_FILE ??
    process.env.ORCA_OPENSHELL_POLICY_FILE ??
    (orcaSession && fs.existsSync(defaultOrcaPolicy) ? defaultOrcaPolicy : undefined);
  const projectPolicy = mergePolicies([path.join(projectRoot, '.agents', 'policies')]);
  const policy: OpenShellPolicy = explicitPolicy
    ? mergeTwoPolicies(
        parsePolicyFile(explicitPolicy) ?? (() => { throw new Error(`Cannot load OpenShell policy: ${explicitPolicy}`); })(),
        projectPolicy
      )
    : (discoverAndMergePolicies(projectRoot) ?? { version: 1 });
  if (orcaSession) {
    if (!policy.filesystem_policy) {
      throw new Error('Orca OpenShell launches require a filesystem policy');
    }
    policy.landlock = { compatibility: 'hard_requirement' };
  }
  policy.network_middlewares ??= {};
  policy.network_middlewares.outbound_token_redaction ??= {
    name: 'Redact provider-shaped API tokens in request bodies',
    middleware: 'openshell/regex',
    order: 10,
    config: { mode: 'redact' },
    on_error: 'fail_closed',
    endpoints: { include: ['**'] },
  };

  if (workspaceWritePaths !== null) {
    const homePath = agent.type === 'claude' ? '.claude' : agent.type === 'codex' ? '.codex' : '.gemini';
    applyWorkspaceWriteScope(policy, projectName, homePath, workspaceWritePaths);
  }

  const credentials = await agent.getCredentials();
  const extraProviders = getExtraProviderNames();
  const orcaCodex = agent.type === 'codex' && (process.env.OPENSHELL_BRIDGE_REQUIRED === '1' || structuredSession);
  const providerName = orcaCodex ? 'codex-orca' : agent.providerName;
  assertNoCredentialLeak(projectRoot, credentials);

  const providers = [
    providerName,
    ...extraProviders,
  ];

  const stageDir = fs.mkdtempSync(path.join(os.tmpdir(), `${agent.type}-stage-${process.pid}-`));
  const terminalId =
    process.env.OPENSHELL_BRIDGE_TERMINAL_ID ||
    process.env.ORCA_TERMINAL_HANDLE ||
    (process.env.ORCA_AGENT_SESSION_ID ? `structured-agent-session-${process.env.ORCA_AGENT_SESSION_ID}` : '');
  const workspaceId = resolveOrcaWorkspaceId(projectRoot);
  const enableDelegation = Boolean(terminalId && workspaceId && orcaSession);
  let uploads: Array<{ source: string; destination: string }>;
  try {
    // Stage files before creating the sandbox. OpenShell's create-time uploads
    // make the scoped paths exist before Landlock applies its static policy.
    await agent.stageConfiguration(stageDir, projectRoot, projectName);
    if (enableDelegation) {
      const shimSource = process.env.OPENSHELL_BRIDGE_SHIM_PATH || path.join(os.homedir(), '.local', 'bin', 'orca-delegation-shim.js');
      const shimDir = path.join(stageDir, '.orca-delegate', 'bin');
      fs.mkdirSync(shimDir, { recursive: true });
      fs.copyFileSync(shimSource, path.join(shimDir, 'orca'));
      fs.chmodSync(path.join(shimDir, 'orca'), 0o755);
      fs.writeFileSync(path.join(stageDir, '.orca-delegate', 'package.json'), '{"type":"module"}\n');
    }
    redactCredentialFiles(stageDir, credentials);
    if (orcaCodex) CodexAdapter.prepareOrcaAuth(stageDir, credentials.CODEX_AUTH_ACCOUNT_ID || '');
    const stagedSecrets = orcaCodex
      ? Object.fromEntries(Object.entries(credentials).filter(([key]) => key !== 'CODEX_AUTH_ACCOUNT_ID'))
      : credentials;
    assertNoCredentialLeak(stageDir, stagedSecrets);
    assertNoCredentialLeak(projectRoot, credentials);

    uploads = fs.readdirSync(stageDir).map(item => {
      const source = path.join(stageDir, item);
      const destination = fs.statSync(source).isDirectory() ? '/sandbox' : `/sandbox/${item}`;
      return { source, destination };
    });
    uploads.push({ source: projectRoot, destination: '/sandbox' });
  } catch (err) {
    fs.rmSync(stageDir, { recursive: true, force: true });
    throw err;
  }

  // Provider-backed credentials are resolved by the supervisor. The container
  // receives only OpenShell placeholders, never the host values.
  if (orcaCodex) {
    try { OpenShellSandbox.requireProvider(providerName); }
    catch (err) {
      logDebug(String(err));
      fs.rmSync(stageDir, { recursive: true, force: true });
      return 1;
    }
  } else if (Object.keys(credentials).length > 0) {
    try {
      OpenShellSandbox.provisionProvider(agent.providerName, agent.providerName, credentials);
    } catch (err) {
      logDebug(`Could not provision credential provider ${agent.providerName}: ${err}`);
      fs.rmSync(stageDir, { recursive: true, force: true });
      return 1; // Fail closed; do not fall back to passing credentials into a container.
    }
  }

  // 4. Create OpenShell Sandbox
  let sandbox: OpenShellSandbox;
  try {
    sandbox = OpenShellSandbox.create(
      sandboxName,
      agent.containerImage,
      [...new Set(providers)],
      policy,
      uploads
    );
    registerSandboxSession({
      sandboxName,
      agent: agent.type === 'agy' ? 'antigravity' : agent.type,
      workspacePath: projectRoot,
      workspaceId: process.env.OPENSHELL_BRIDGE_WORKSPACE_ID || undefined,
      terminalId: process.env.OPENSHELL_BRIDGE_TERMINAL_ID || undefined,
      agentSessionId: process.env.ORCA_AGENT_SESSION_ID || undefined,
      pid: process.pid,
    });
  } catch (err) {
    logDebug(`Failed to create sandbox: ${err}. Refusing to run outside the sandbox.`);
    // OpenShell may retain an Error-phase sandbox after a failed create.
    new OpenShellSandbox(sandboxName).delete();
    fs.rmSync(stageDir, { recursive: true, force: true });
    return 1;
  }

  let cleanupDone = false;
  let syncing = false;
  let dirtySinceLastSync = true;
  let broker: DelegationBroker | null = null;

  // Spawn a lightweight parent-PID watchdog so that even if Orca's teardown
  // supervisor sends SIGKILL to this bridge process, the OpenShell sandbox is
  // guaranteed to be deleted once this process exits.
  let watchdogPid: number | undefined;
  try {
    const watchdog = spawn(
      process.execPath,
      [
        '-e',
        `const { execFileSync } = require('node:child_process');
         const ppid = Number(process.argv[1]);
         const name = process.argv[2];
         const timer = setInterval(() => {
           try { process.kill(ppid, 0); } catch {
             clearInterval(timer);
             try { execFileSync('openshell', ['sandbox', 'delete', name], { stdio: 'ignore', timeout: 15000 }); } catch {}
             process.exit(0);
           }
         }, 1000);`,
        String(process.pid),
        sandboxName,
      ],
      { detached: true, stdio: 'ignore' }
    );
    watchdogPid = watchdog.pid;
    watchdog.unref();
  } catch {}

  const syncSandboxToHost = async (): Promise<void> => {
    if (syncing) return;
    syncing = true;
    try {
      if (baseline) {
        if (workspaceWritePaths?.length !== 0) {
          const downloadRoot = fs.mkdtempSync(path.join(os.tmpdir(), `orca-download-${sandboxName}-`));
          const downloaded = path.join(downloadRoot, 'workspace');
          fs.mkdirSync(downloaded);
          try {
            if (!sandbox.download(`/sandbox/${projectName}`, downloaded)) throw new Error('Sandbox download failed');
            const conflictRoot = path.join(os.homedir(), '.orca', 'openshell-conflicts', sandboxName);
            const result = mergeWorkspace(projectRoot, downloaded, baseline, workspaceWritePaths, conflictRoot);
            baseline = snapshotWorkspace(projectRoot);
            logDebug(`Workspace merge for ${sandboxName}: ${result.applied} changes applied, ${result.conflicts.length} conflicts${result.conflicts.length ? ` at ${conflictRoot}` : ''}`);
          } finally { fs.rmSync(downloadRoot, { recursive: true, force: true }); }
        }
        if (agent.type === 'claude') {
          await (agent as ClaudeAdapter).syncTranscriptsOnly(sandboxName, projectRoot, projectName);
        }
      } else {
        await agent.syncBack(sandboxName, projectRoot, projectName, workspaceWritePaths);
      }
      dirtySinceLastSync = false;
    } catch (e) {
      logDebug(`Sync back error: ${e}`);
    } finally {
      syncing = false;
    }
  };

  let sessionHibernated = false;

  const syncHostChangesToSandbox = (sshConfigPath: string, sshConfigContent: string): void => {
    if (!baseline) return;
    try {
      const currentHost = snapshotWorkspace(projectRoot);
      const changedRelatives: string[] = [];
      const deletedRelatives: string[] = [];

      for (const [rel, entry] of currentHost.entries()) {
        const prev = baseline.get(rel);
        if (JSON.stringify(prev) !== JSON.stringify(entry) && entry.kind === 'file') {
          changedRelatives.push(rel);
        }
      }
      for (const rel of baseline.keys()) {
        if (!currentHost.has(rel)) {
          deletedRelatives.push(rel);
        }
      }

      for (const rel of changedRelatives) {
        const srcPath = path.join(projectRoot, rel);
        const dstDir = path.posix.dirname(path.posix.join('/sandbox', projectName, ...rel.split(path.sep)));
        try {
          sandbox.upload(srcPath, dstDir, true);
        } catch (err) {
          logDebug(`Host-to-sandbox upload warning for ${rel}: ${err}`);
        }
      }

      if (deletedRelatives.length > 0) {
        const hostMatch = sshConfigContent.match(/^\s*Host\s+(\S+)/m);
        if (hostMatch) {
          const rmTargets = deletedRelatives
            .map(rel => shellQuote(path.posix.join('/sandbox', projectName, ...rel.split(path.sep))))
            .join(' ');
          try {
            execFileSync('ssh', ['-T', '-F', sshConfigPath, hostMatch[1], `rm -f ${rmTargets}`], {
              stdio: ['ignore', 'ignore', 'ignore'],
              timeout: 8000,
            });
          } catch {}
        }
      }

      if (changedRelatives.length > 0 || deletedRelatives.length > 0) {
        baseline = currentHost;
        logDebug(`Synced ${changedRelatives.length} modified and ${deletedRelatives.length} deleted host file(s) into resumed sandbox ${sandboxName}`);
      }
    } catch (err) {
      logDebug(`Host-to-sandbox sync error on wake: ${err}`);
    }
  };

  const cleanup = async (): Promise<void> => {
    if (cleanupDone) return;
    cleanupDone = true;
    logDebug(`Cleaning up sandbox ${sandboxName}`);
    unregisterSandboxSession(sandboxName);
    broker?.stop();
    forgetLaunch(terminalId);
    revokeGrant(terminalId);
    if (dirtySinceLastSync && !sessionHibernated) {
      await syncSandboxToHost();
    }
    sandbox.delete();
    if (watchdogPid) {
      try { process.kill(watchdogPid, 'SIGTERM'); } catch {}
    }
  };

  let runningExec: ReturnType<typeof spawn> | null = null;
  let onTerminateSignal: ((signal: NodeJS.Signals) => void) | null = null;
  const handleSignal = (signal: NodeJS.Signals) => {
    if (onTerminateSignal) {
      onTerminateSignal(signal);
      return;
    }
    // Let the OpenShell exec/ssh session terminate before downloading or deleting its sandbox.
    runningExec?.kill(signal);
  };

  for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP'] as const) {
    process.on(signal, () => handleSignal(signal));
  }
  process.once('exit', () => {
    if (!cleanupDone) {
      unregisterSandboxSession(sandboxName);
      forgetLaunch(terminalId);
      revokeGrant(terminalId);
      sandbox.delete(true);
    }
  });

  try {
    // 7. Execute agent inside sandbox
    if (enableDelegation) {
      recordLaunch(terminalId, workspaceId, sandboxName);
      if (!readGrant(terminalId, workspaceId)) {
        const configPath = path.join(projectRoot, '.agents', 'delegation.json');
        let autoConfig: { autoGrant?: boolean; agents?: Array<'codex' | 'claude' | 'antigravity' | 'agy'>; maxWorkers?: number; maxDepth?: number } | null = null;
        if (fs.existsSync(configPath)) {
          try { autoConfig = JSON.parse(fs.readFileSync(configPath, 'utf8')); } catch {}
        }
        if (process.env.ORCA_AUTO_GRANT_DELEGATION === '1' || autoConfig?.autoGrant) {
          try {
            writeGrant({
              terminal: terminalId,
              workspace: `id:${workspaceId}`,
              agents: autoConfig?.agents || ['claude', 'antigravity', 'codex'],
              maxWorkers: autoConfig?.maxWorkers ?? 2,
              depth: 0,
              maxDepth: autoConfig?.maxDepth ?? 1,
            });
            logDebug(`Auto-granted delegation for coordinator terminal ${terminalId} in ${workspaceId}`);
          } catch (err) {
            logDebug(`Failed to auto-grant delegation: ${err}`);
          }
        }
      }
      broker = new DelegationBroker(sandboxName, terminalId, workspaceId, projectRoot);
      broker.start();
    }

    const buildAgentExecArgs = (argsForRun: string[]): string[] => {
      const built = agent.buildExecArgs(sandboxName, projectName, argsForRun, credentials);
      if (enableDelegation && broker) {
        const separator = built.indexOf('--');
        if (separator < 0) throw new Error('Agent adapter has no OpenShell command separator');
        built.splice(
          separator,
          0,
          '--env',
          `ORCA_DELEGATION_DIR=${broker.sandboxDir}`,
          '--env',
          'PATH=/sandbox/.orca-delegate/bin:/usr/local/go/bin:/home/ubuntu/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
        );
      }
      return built;
    };

    const jsonStreamMode =
      (agent.type === 'codex' && rawArgs.includes('app-server')) ||
      (agent.type === 'claude' && ClaudeAdapter.isStreamJsonMode(rawArgs));

    if (!jsonStreamMode) {
      const execArgs = buildAgentExecArgs(rawArgs);
      return await new Promise<number>((resolve) => {
        const child = spawn('openshell', execArgs, { stdio: 'inherit' });
        runningExec = child;
        child.on('close', (code, signal) => {
          runningExec = null;
          resolve(code ?? (signal ? 128 + (os.constants.signals[signal] ?? 1) : 1));
        });
        child.on('error', (err) => {
          logDebug(`Child process error: ${err}`);
          resolve(1);
        });
      });
    }

    // Structured JSON-RPC / stream-json session with automatic idle hibernation & transparent wake
    const containerRoot = `/sandbox/${projectName}`;
    const sshConfigPath = path.join(stageDir, 'ssh_config');
    const tracker = new StreamSessionTracker(agent.type, rawArgs);

    const refreshSshConfig = (): string => {
      const content = execFileSync('openshell', ['sandbox', 'ssh-config', sandboxName], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
        timeout: 10000,
      });
      fs.writeFileSync(sshConfigPath, content, { mode: 0o600 });
      return content;
    };

    return await new Promise<number>((resolve) => {
      type Lifecycle = 'running' | 'hibernating' | 'hibernated' | 'waking' | 'closed';
      let lifecycle: Lifecycle = 'running';
      let settled = false;
      let hostStdinEnded = false;
      let terminateSignal: NodeJS.Signals | null = null;
      let warmupPending = false;
      let lastActivityAt = Date.now();
      const bufferedHostLines: string[] = [];
      let hostPendingBuf = Buffer.alloc(0);

      const finish = (exitCode: number) => {
        if (settled) return;
        settled = true;
        lifecycle = 'closed';
        clearInterval(idleTimer);
        process.stdin.removeListener('data', onHostData);
        process.stdin.removeListener('end', onHostEnd);
        process.stdin.removeListener('close', onHostEnd);
        resolve(exitCode);
      };

      onTerminateSignal = (sig: NodeJS.Signals) => {
        terminateSignal = sig;
        if (lifecycle === 'hibernated') {
          finish(0);
          return;
        }
        runningExec?.kill(sig);
      };

      const flushBufferedHostLines = () => {
        if (warmupPending || lifecycle !== 'running' || !runningExec?.stdin) return;
        while (bufferedHostLines.length > 0) {
          const nextLine = bufferedHostLines.shift()!;
          dirtySinceLastSync = true;
          lastActivityAt = Date.now();
          runningExec.stdin.write(`${nextLine}\n`);
        }
        if (hostStdinEnded && runningExec?.stdin) {
          try { runningExec.stdin.end(); } catch {}
        }
      };

      const spawnStreamChild = (isResumed: boolean) => {
        const sshConfigContent = refreshSshConfig();
        if (isResumed) {
          syncHostChangesToSandbox(sshConfigPath, sshConfigContent);
        }
        const runArgs = isResumed ? tracker.buildResumedRawArgs(rawArgs) : rawArgs;
        const execArgs = buildAgentExecArgs(runArgs);
        const sshArgs = buildStreamingSshArgs(execArgs, sshConfigContent, sshConfigPath);

        const child = spawn('ssh', sshArgs, { stdio: ['pipe', 'pipe', 'inherit'] });
        runningExec = child;
        lifecycle = 'running';
        sessionHibernated = false;
        lastActivityAt = Date.now();

        if (isResumed && child.stdin) {
          const warmup = tracker.prepareResumeWarmup();
          warmupPending = warmup.waitForWarmup;
          for (const frame of warmup.initialFrames) {
            child.stdin.write(`${frame}\n`);
          }
        } else {
          warmupPending = false;
        }

        flushBufferedHostLines();

        let childPendingBuf = Buffer.alloc(0);
        let stdoutChain = Promise.resolve();

        const handleContainerLine = async (rawLine: string) => {
          const line = rawLine.replace(/\r$/, '');
          lastActivityAt = Date.now();
          const obs = tracker.observeContainerFrame(line, isResumed);
          for (const followUp of obs.followUpFrames) {
            try {
              child.stdin?.write(`${followUp}\n`);
            } catch {}
          }
          if (warmupPending && obs.warmupComplete) {
            warmupPending = false;
            flushBufferedHostLines();
          }
          if (obs.suppress) return;

          if (isTurnCompleteFrame(line)) {
            try {
              await syncSandboxToHost();
            } catch {}
          }
          process.stdout.write(`${rewriteJsonRpcPaths(line, projectRoot, containerRoot, 'containerToHost')}\n`);
        };

        child.stdout?.on('data', (chunk: Buffer) => {
          childPendingBuf = Buffer.concat([childPendingBuf, chunk]);
          let nl: number;
          while ((nl = childPendingBuf.indexOf(0x0a)) !== -1) {
            const lineStr = childPendingBuf.subarray(0, nl).toString('utf8');
            childPendingBuf = childPendingBuf.subarray(nl + 1);
            stdoutChain = stdoutChain.then(() => handleContainerLine(lineStr)).catch(() => {});
          }
        });

        child.on('close', (code, signal) => {
          if (childPendingBuf.length > 0) {
            const rem = childPendingBuf.toString('utf8');
            childPendingBuf = Buffer.alloc(0);
            stdoutChain = stdoutChain.then(() => handleContainerLine(rem)).catch(() => {});
          }
          void stdoutChain.finally(() => {
            if (runningExec === child) runningExec = null;
            if (lifecycle === 'hibernating' || lifecycle === 'hibernated' || lifecycle === 'waking' || lifecycle === 'closed') {
              return;
            }
            if (!hostStdinEnded && !terminateSignal) {
              const phase = sandbox.getPhase();
              if (phase === 'Stopped' && tracker.sessionId) {
                logDebug(`Sandbox ${sandboxName} was paused externally; entering hibernated state`);
                broker?.stop();
                dirtySinceLastSync = false;
                sessionHibernated = true;
                lifecycle = 'hibernated';
                if (bufferedHostLines.length > 0) {
                  void wakeSession();
                }
                return;
              }
            }
            finish(code ?? (signal ? 128 + (os.constants.signals[signal] ?? 1) : 1));
          });
        });

        child.on('error', (err) => {
          logDebug(`Child process error: ${err}`);
          if (lifecycle === 'running') {
            finish(1);
          }
        });
      };

      const wakeSession = async () => {
        if (lifecycle === 'waking' || lifecycle === 'closed') return;
        lifecycle = 'waking';
        lastActivityAt = Date.now();
        try {
          const phase = sandbox.getPhase();
          if (phase === null) {
            logDebug(`Sandbox ${sandboxName} no longer exists; closing session`);
            finish(1);
            return;
          }
          if (phase !== 'Ready') {
            logDebug(`Waking hibernated sandbox ${sandboxName} (phase=${phase})`);
            if (!sandbox.start()) {
              logDebug(`Failed to restart sandbox ${sandboxName}`);
              finish(1);
              return;
            }
          }
          if (enableDelegation && broker) {
            try {
              broker.start();
            } catch (err) {
              logDebug(`Delegation broker restart warning: ${err}`);
            }
          }
          spawnStreamChild(true);
        } catch (err) {
          logDebug(`Error waking sandbox ${sandboxName}: ${err}`);
          finish(1);
        }
      };

      const hibernateSession = async () => {
        if (lifecycle !== 'running' || !tracker.canHibernate()) return;
        lifecycle = 'hibernating';
        logDebug(`Idle timeout reached for ${sandboxName}; syncing workspace and stopping sandbox`);
        try {
          if (dirtySinceLastSync) {
            await syncSandboxToHost();
          }
        } catch {}
        broker?.stop();
        const activeChild = runningExec;
        runningExec = null;
        try {
          activeChild?.stdin?.end();
          activeChild?.kill('SIGTERM');
        } catch {}

        if (sandbox.stop()) {
          sessionHibernated = true;
          lifecycle = 'hibernated';
        } else {
          // Could not stop container; resume immediately
          await wakeSession();
          return;
        }

        if (hostStdinEnded || terminateSignal) {
          finish(0);
          return;
        }
        if (bufferedHostLines.length > 0) {
          await wakeSession();
        }
      };

      const handleHostLine = (rawLine: string) => {
        const line = rawLine.replace(/\r$/, '');
        if (!line.trim()) return;
        lastActivityAt = Date.now();
        const rewritten = rewriteJsonRpcPaths(line, projectRoot, containerRoot, 'hostToContainer');
        tracker.observeHostFrame(rewritten);
        bufferedHostLines.push(rewritten);
        if (lifecycle === 'running') {
          flushBufferedHostLines();
        } else if (lifecycle === 'hibernated') {
          void wakeSession();
        }
      };

      const onHostData = (chunk: Buffer) => {
        hostPendingBuf = Buffer.concat([hostPendingBuf, chunk]);
        let nl: number;
        while ((nl = hostPendingBuf.indexOf(0x0a)) !== -1) {
          const lineStr = hostPendingBuf.subarray(0, nl).toString('utf8');
          hostPendingBuf = hostPendingBuf.subarray(nl + 1);
          handleHostLine(lineStr);
        }
      };

      const onHostEnd = () => {
        if (hostPendingBuf.length > 0) {
          const rem = hostPendingBuf.toString('utf8');
          hostPendingBuf = Buffer.alloc(0);
          handleHostLine(rem);
        }
        hostStdinEnded = true;
        if (lifecycle === 'hibernated') {
          finish(0);
        } else if (lifecycle === 'running' && bufferedHostLines.length === 0 && runningExec?.stdin) {
          try { runningExec.stdin.end(); } catch {}
        }
      };

      process.stdin.on('data', onHostData);
      process.stdin.once('end', onHostEnd);
      process.stdin.once('close', onHostEnd);

      const idleTimer = setInterval(() => {
        if (lifecycle !== 'running') return;
        const idleTimeoutSec = getSandboxIdleTimeoutSeconds(undefined, {
          sandboxName,
          agentSessionId: process.env.ORCA_AGENT_SESSION_ID,
          terminalId,
        });
        if (idleTimeoutSec <= 0) return;
        if (!tracker.canHibernate()) return;
        if (Date.now() - lastActivityAt >= idleTimeoutSec * 1000) {
          void hibernateSession();
        }
      }, 2000);
      idleTimer.unref?.();

      spawnStreamChild(false);
    });
  } finally {
    try {
      fs.rmSync(stageDir, { recursive: true, force: true });
    } catch {}
    await cleanup();
  }
}

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

export function buildStreamingSshArgs(
  execArgs: string[],
  sshConfigContent: string,
  sshConfigPath: string
): string[] {
  const hostMatch = sshConfigContent.match(/^\s*Host\s+(\S+)/m);
  if (!hostMatch) {
    throw new Error('Could not parse Host alias from openshell sandbox ssh-config');
  }
  const hostAlias = hostMatch[1];

  const sep = execArgs.indexOf('--');
  const header = sep >= 0 ? execArgs.slice(0, sep) : execArgs;
  const cmdParts = sep >= 0 ? execArgs.slice(sep + 1) : [];

  let workdir = '';
  const envs: string[] = [];
  for (let i = 0; i < header.length; i++) {
    if (header[i] === '--workdir' && i + 1 < header.length) {
      workdir = header[++i];
    } else if (header[i] === '--env' && i + 1 < header.length) {
      envs.push(header[++i]);
    }
  }

  const statements: string[] = [];
  if (workdir) statements.push(`cd ${shellQuote(workdir)}`);
  for (const envPair of envs) {
    statements.push(`export ${shellQuote(envPair)}`);
  }
  statements.push(`exec ${cmdParts.map(shellQuote).join(' ')}`);
  const innerScript = statements.join(' && ');
  const remoteCommand = `bash -lc ${shellQuote(innerScript)}`;

  return ['-T', '-F', sshConfigPath, hostAlias, remoteCommand];
}
