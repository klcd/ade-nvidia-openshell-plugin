import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, execFileSync } from 'node:child_process';
import type { AgentAdapter, OpenShellPolicy } from './types.js';
import {
  detectProjectRoot,
  generateSandboxName,
  findHostBinary,
  logDebug,
} from './config.js';
import { discoverAndMergePolicies, mergePolicies, mergeTwoPolicies, parsePolicyFile } from './policy.js';
import { OpenShellSandbox } from './sandbox.js';
import { assertNoCredentialLeak, redactCredentialFiles } from './credential-security.js';
import { createJsonRpcPathTransform } from './protocols/jsonrpc.js';
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

export async function runSandboxSession(agent: AgentAdapter, rawArgs: string[]): Promise<number> {
  const cwd = process.cwd();

  // 1. Check for fast-path bypass
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

  // 2. Discover workspace and generate sandbox name
  const projectRoot = detectProjectRoot(cwd);
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

  const cleanup = async (): Promise<void> => {
    if (cleanupDone) return;
    cleanupDone = true;
    logDebug(`Cleaning up sandbox ${sandboxName}`);
    broker?.stop();
    forgetLaunch(terminalId);
    revokeGrant(terminalId);
    if (dirtySinceLastSync) {
      await syncSandboxToHost();
    }
    sandbox.delete();
    if (watchdogPid) {
      try { process.kill(watchdogPid, 'SIGTERM'); } catch {}
    }
  };

  let runningExec: ReturnType<typeof spawn> | null = null;
  const handleSignal = (signal: NodeJS.Signals) => {
    // Let the OpenShell exec/ssh session terminate before downloading or deleting its sandbox.
    runningExec?.kill(signal);
  };

  for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP'] as const) {
    process.on(signal, () => handleSignal(signal));
  }
  process.once('exit', () => {
    if (!cleanupDone) {
      forgetLaunch(terminalId);
      revokeGrant(terminalId);
      sandbox.delete(true);
    }
  });

  try {
    // 7. Execute agent inside sandbox
    const execArgs = agent.buildExecArgs(sandboxName, projectName, rawArgs, credentials);
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
      const separator = execArgs.indexOf('--');
      if (separator < 0) throw new Error('Agent adapter has no OpenShell command separator');
      execArgs.splice(separator, 0,
        '--env', `ORCA_DELEGATION_DIR=${broker.sandboxDir}`,
        '--env', 'PATH=/sandbox/.orca-delegate/bin:/usr/local/go/bin:/home/ubuntu/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin');
    }

    const jsonStreamMode =
      (agent.type === 'codex' && rawArgs.includes('app-server')) ||
      (agent.type === 'claude' && ClaudeAdapter.isStreamJsonMode(rawArgs));

    let spawnCommand = 'openshell';
    let spawnArgs = execArgs;
    if (jsonStreamMode) {
      // `openshell sandbox exec` buffers stdin until EOF before calling the
      // unary ExecSandbox RPC, which breaks persistent bidirectional protocols
      // (`claude --input-format stream-json` and `codex app-server`).
      // Use `ssh -T` via `openshell sandbox ssh-config` for real-time full-duplex streaming.
      const sshConfigContent = execFileSync('openshell', ['sandbox', 'ssh-config', sandboxName], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
        timeout: 10000,
      });
      const sshConfigPath = path.join(stageDir, 'ssh_config');
      fs.writeFileSync(sshConfigPath, sshConfigContent, { mode: 0o600 });
      spawnCommand = 'ssh';
      spawnArgs = buildStreamingSshArgs(execArgs, sshConfigContent, sshConfigPath);
    }

    return await new Promise<number>((resolve) => {
      const child = spawn(spawnCommand, spawnArgs, {
        stdio: jsonStreamMode ? ['pipe', 'pipe', 'inherit'] : 'inherit',
      });
      runningExec = child;

      if (jsonStreamMode && child.stdin && child.stdout) {
        const containerRoot = `/sandbox/${projectName}`;
        process.stdin.on('data', () => {
          dirtySinceLastSync = true;
        });
        process.stdin
          .pipe(createJsonRpcPathTransform(projectRoot, containerRoot, 'hostToContainer'))
          .pipe(child.stdin);
        child.stdout
          .pipe(createJsonRpcPathTransform(projectRoot, containerRoot, 'containerToHost', syncSandboxToHost))
          .pipe(process.stdout);
      }

      child.on('close', (code, signal) => {
        runningExec = null;
        resolve(code ?? (signal ? 128 + (os.constants.signals[signal] ?? 1) : 1));
      });
      child.on('error', (err) => {
        logDebug(`Child process error: ${err}`);
        resolve(1);
      });
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
