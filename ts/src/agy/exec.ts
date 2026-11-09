import { execFileSync, spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { isSandboxModeEnabled, logDebug, USER_HOME } from '../config.js';
import { ensureValidHostTmpDir } from '../sandbox.js';
import { ensureAgySandboxReady } from './daemon.js';
import {
  detectBlockedEgress,
  drainL7RequestQueue,
  promptUserForL7Approval,
  runAgyPolicyAdd,
} from './egress.js';
import {
  acquireAgyExecLock,
  getAgySessionDir,
  resolveAgyProjectRoot,
  shellQuote,
  touchAgyActivity,
  translateAgyCommandAndCwd,
  type AgyChatSandboxState,
} from './state.js';
import { syncHostDeltaToSandbox, syncSandboxDeltaToHost } from './sync.js';

async function runRemoteSshCaptured(
  state: AgyChatSandboxState,
  remoteScript: string
): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  return new Promise(resolve => {
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

function resolveRealHostShell(shellName: string): string {
  const base = path.basename(shellName) === 'bash' ? 'bash' : 'zsh';
  const user = process.env.USER || 'cedric';
  const candidates = [
    `/etc/profiles/per-user/${user}/bin/${base}`,
    `/run/current-system/sw/bin/${base}`,
    `/bin/${base}`,
  ];
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) return candidate;
  }
  return `/bin/${base}`;
}

export async function runAgyChatExec(shellName: string, commandLine: string): Promise<number> {
  process.env.AG_SANDBOX_HOST_INTERNAL = '1';
  delete process.env.ANTIGRAVITY_HARNESS_PATH;

  const trimmedCmd = commandLine.trim();
  if (trimmedCmd.startsWith('openshell-l7-allow ')) {
    const rawTokens =
      trimmedCmd
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

  if (!isSandboxModeEnabled(USER_HOME, projectRoot)) {
    const realShell = resolveRealHostShell(shellName);
    logDebug(
      `Sandbox mode disabled for ${projectRoot} - executing Antigravity Chat command on host via ${realShell}`
    );
    return new Promise<number>(resolve => {
      const child = spawn(realShell, ['-c', commandLine], {
        stdio: 'inherit',
        env: process.env,
      });
      child.on('close', (code, signal) => {
        resolve(code ?? (signal ? 128 + (os.constants.signals[signal] ?? 1) : 0));
      });
      child.on('error', () => resolve(1));
    });
  }

  ensureValidHostTmpDir();
  const releaseExecLock = acquireAgyExecLock(sessionDir);
  touchAgyActivity(sessionDir);
  try {
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
          '--project-root', state.projectRoot,
          ...(blocked.commandLine ? ['--trigger-command', blocked.commandLine] : []),
        ]);

        // runAgyPolicyAdd uses `openshell policy update --wait`, so the policy revision is already loaded
        for (let attempt = 0; attempt < 4; attempt++) {
          if (attempt > 0) execFileSync('sleep', ['1']);
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
    await drainL7RequestQueue(state.projectRoot, state.sandboxName);

    return exitCode;
  } finally {
    touchAgyActivity(sessionDir);
    releaseExecLock();
  }
}
