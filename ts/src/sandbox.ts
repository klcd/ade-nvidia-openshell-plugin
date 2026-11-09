import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFileSync, spawn } from 'node:child_process';
import type { OpenShellPolicy } from './types.js';
import { logDebug } from './config.js';

export function ensureValidHostTmpDir(): void {
  const cur = process.env.TMPDIR;
  if (cur && (cur.includes('/oacp-') || !fs.existsSync(cur))) {
    process.env.TMPDIR = '/tmp';
  }
}

export function spawnSandboxLifecycleWatchdog(
  watchedPid: number,
  sandboxName: string
): number | undefined {
  try {
    const watchdog = spawn(
      process.execPath,
      [
        '-e',
        `const { execFileSync } = require('node:child_process');
         const ppid = Number(process.argv[1]);
         const name = process.argv[2];
         let deleting = false;
         const timer = setInterval(() => {
           if (deleting) return;
           try { process.kill(ppid, 0); } catch {
             deleting = true;
             clearInterval(timer);
             let attempts = 0;
             const tryDelete = () => {
               attempts++;
               try {
                 execFileSync('openshell', ['sandbox', 'delete', name], { stdio: 'ignore', timeout: 15000 });
                 process.exit(0);
               } catch {
                 if (attempts >= 3) process.exit(0);
                 setTimeout(tryDelete, 1500);
               }
             };
             tryDelete();
           }
         }, 1000);`,
        String(watchedPid),
        sandboxName,
      ],
      { detached: true, stdio: 'ignore', env: { ...process.env, TMPDIR: '/tmp' } }
    );
    watchdog.unref();
    return watchdog.pid;
  } catch {
    return undefined;
  }
}

export class OpenShellSandbox {
  constructor(public readonly name: string) {
    ensureValidHostTmpDir();
  }

  public static create(
    name: string,
    image: string,
    providers: string[],
    policy: OpenShellPolicy | null,
    uploads: Array<{ source: string; destination: string }> = []
  ): OpenShellSandbox {
    ensureValidHostTmpDir();
    OpenShellSandbox.checkPolicyBoundary(name, policy);
    const cmdArgs = [
      'sandbox', 'create',
      '--name', name,
      '--from', image,
      '--detach',
    ];

    const cpu = process.env.ORCA_SANDBOX_CPU;
    if (cpu) {
      if (!/^(?:\d+(?:\.\d+)?|\d+m)$/.test(cpu)) throw new Error('Invalid ORCA_SANDBOX_CPU quantity');
      cmdArgs.push('--cpu', cpu);
    }
    const memory = process.env.ORCA_SANDBOX_MEMORY;
    if (memory) {
      if (!/^\d+(?:\.\d+)?(?:Ki|Mi|Gi|Ti|K|M|G|T)?$/.test(memory)) {
        throw new Error('Invalid ORCA_SANDBOX_MEMORY quantity');
      }
      cmdArgs.push('--memory', memory);
    }

    for (const p of providers) cmdArgs.push('--provider', p);

    let tmpPolicyPath: string | null = null;
    let tmpPolicyDir: string | null = null;
    if (policy) {
      tmpPolicyDir = fs.mkdtempSync(path.join(os.tmpdir(), `openshell-policy-${name}-`));
      tmpPolicyPath = path.join(tmpPolicyDir, 'policy.json');
      fs.writeFileSync(tmpPolicyPath, JSON.stringify(policy, null, 2), { mode: 0o600 });
      cmdArgs.push('--policy', tmpPolicyPath);
    }
    if (uploads.length > 0) cmdArgs.push('--no-git-ignore');
    for (const upload of uploads) {
      cmdArgs.push('--upload', `${upload.source}:${upload.destination}`);
    }

    try {
      execFileSync('openshell', cmdArgs, { stdio: ['ignore', 'ignore', 'pipe'] });
      logDebug(`Created sandbox ${name} (image: ${image})`);
    } catch (error) {
      const stderr = (error as { stderr?: Buffer | string }).stderr;
      if (stderr) logDebug(`OpenShell create error for ${name}: ${String(stderr).trim().slice(0, 2000)}`);
      throw error;
    } finally {
      if (tmpPolicyDir) {
        try { fs.rmSync(tmpPolicyDir, { recursive: true, force: true }); } catch {}
      }
    }

    return new OpenShellSandbox(name);
  }

  private static checkPolicyBoundary(name: string, policy: OpenShellPolicy | null): void {
    const boundaryPath = process.env.ORCA_SANDBOX_BOUNDARY_POLICY;
    if (!boundaryPath) return;
    if (!policy?.filesystem_policy) {
      throw new Error('A filesystem policy is required when ORCA_SANDBOX_BOUNDARY_POLICY is set');
    }

    const candidateDir = fs.mkdtempSync(path.join(os.tmpdir(), `openshell-boundary-${name}-`));
    const candidatePath = path.join(candidateDir, 'candidate.json');
    const candidate: OpenShellPolicy = {
      version: policy.version,
      filesystem_policy: policy.filesystem_policy,
      landlock: policy.landlock,
      process: policy.process,
    };
    fs.writeFileSync(candidatePath, JSON.stringify(candidate, null, 2), { mode: 0o600 });
    try {
      const result = execFileSync('openshell-prover', [
        'check', candidatePath, '--boundary', path.resolve(boundaryPath), '--output', 'json',
      ], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
      const parsed = JSON.parse(result) as {
        result?: string;
        coverage?: { domains?: string[] };
      };
      if (parsed.result !== 'within_boundary' || !parsed.coverage?.domains?.includes('filesystem')) {
        throw new Error('Policy prover did not confirm filesystem containment');
      }
      logDebug(`Sandbox policy ${name} passed the configured master boundary`);
    } catch (err) {
      logDebug(`Sandbox policy ${name} failed the configured master boundary: ${err}`);
      throw new Error(`Sandbox policy failed the configured master boundary: ${err}`);
    } finally {
      try { fs.rmSync(candidateDir, { recursive: true, force: true }); } catch {}
    }
  }

  /** Store credentials in the OpenShell gateway provider; the workload receives placeholders only. */
  public static provisionProvider(
    providerName: string,
    profileName: string,
    credentials: Record<string, string>
  ): void {
    const env = { ...process.env, ...credentials };
    let acceptedKeys: string[] | null = null;
    try {
      const profileYaml = execFileSync('openshell', ['profile', 'export', profileName], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 15000 });
      const matches = profileYaml.matchAll(/^\s*-\s*([A-Z0-9_]+)\s*$/gm);
      const keys = [...matches].map(m => m[1]);
      if (keys.length > 0) acceptedKeys = keys;
    } catch {}

    const keysToProvision = acceptedKeys
      ? Object.keys(credentials).filter(k => acceptedKeys!.includes(k))
      : Object.keys(credentials);

    const credArgs = keysToProvision.flatMap(k => ['--credential', k]);
    const args = credArgs.length > 0 ? credArgs : ['--from-existing'];
    try {
      execFileSync('openshell', [
        'provider', 'create', '--name', providerName, '--type', profileName, ...args,
      ], { env, stdio: ['ignore', 'ignore', 'ignore'] });
      logDebug(`Created credential provider ${providerName} from local credentials`);
    } catch {
      // Existing providers are rotated in place. The values are read from this
      // process environment by OpenShell and never passed as command arguments.
      execFileSync('openshell', [
        'provider', 'update', providerName, ...args,
      ], { env, stdio: ['ignore', 'ignore', 'ignore'] });
      logDebug(`Updated credential provider ${providerName} from local credentials`);
    }
  }

  /** Orca's Codex provider is configured separately with gateway-owned refresh material. */
  public static requireProvider(name: string): void {
    try {
      execFileSync('openshell', ['provider', 'get', name], { stdio: ['ignore', 'ignore', 'ignore'], timeout: 15000 });
      const status = execFileSync('openshell', ['provider', 'refresh', 'status', name, '--credential-key', 'CODEX_AUTH_ACCESS_TOKEN'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 15000 });
      if (!new RegExp(`\\b${name}\\s+CODEX_AUTH_ACCESS_TOKEN\\s+oauth2_refresh_token\\s+(refreshed|healthy)\\b`).test(status)) {
        throw new Error('Gateway OAuth refresh is not healthy');
      }
    } catch {
      throw new Error(`OpenShell provider ${name} is unavailable or lacks OAuth refresh; run the host provider setup`);
    }
  }

  public upload(src: string, dst: string, noGitIgnore = false): void {
    const args = ['sandbox', 'upload'];
    if (noGitIgnore) {
      args.push('--no-git-ignore');
    }
    args.push(this.name, src, dst);
    execFileSync('openshell', args, { stdio: ['ignore', 'ignore', 'ignore'] });
  }

  public download(src: string, dst: string): boolean {
    try {
      execFileSync('openshell', ['sandbox', 'download', this.name, src, dst], {
        stdio: ['ignore', 'ignore', 'ignore'],
        timeout: 15000,
      });
      return true;
    } catch (err) {
      logDebug(`Download from ${src} to ${dst} failed: ${err}`);
      return false;
    }
  }

  private spawnDetachedDeleteRetry(): void {
    try {
      const child = spawn(
        process.execPath,
        [
          '-e',
          `const { execFileSync } = require('node:child_process');
           const name = process.argv[1];
           let attempts = 0;
           const tryDelete = () => {
             attempts++;
             try {
               execFileSync('openshell', ['sandbox', 'delete', name], { stdio: 'ignore', timeout: 15000 });
               process.exit(0);
             } catch {
               if (attempts >= 3) process.exit(0);
               setTimeout(tryDelete, 1500);
             }
           };
           tryDelete();`,
          this.name,
        ],
        {
          detached: true,
          stdio: 'ignore',
          env: { ...process.env, TMPDIR: '/tmp' },
        }
      );
      child.unref();
      logDebug(`Scheduled detached deletion for sandbox ${this.name}`);
    } catch (err) {
      logDebug(`Failed to schedule detached deletion for sandbox ${this.name}: ${err}`);
    }
  }

  public delete(detached = false): void {
    ensureValidHostTmpDir();
    if (detached) {
      this.spawnDetachedDeleteRetry();
      return;
    }

    try {
      execFileSync('openshell', ['sandbox', 'delete', this.name], {
        stdio: ['ignore', 'ignore', 'ignore'],
        timeout: 15000,
      });
      logDebug(`Deleted sandbox ${this.name}`);
      return;
    } catch (err) {
      logDebug(`First delete attempt failed for sandbox ${this.name}: ${err}`);
    }

    if (this.getPhase() === null) {
      return;
    }

    try {
      execFileSync('sleep', ['0.5']);
      execFileSync('openshell', ['sandbox', 'delete', this.name], {
        stdio: ['ignore', 'ignore', 'ignore'],
        timeout: 15000,
      });
      logDebug(`Deleted sandbox ${this.name} on retry`);
    } catch (retryErr) {
      logDebug(`Retry delete failed for sandbox ${this.name}, scheduling detached cleanup: ${retryErr}`);
      this.spawnDetachedDeleteRetry();
    }
  }

  public getPhase(): string | null {
    try {
      const out = execFileSync('openshell', ['sandbox', 'list', '-o', 'json'], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
        timeout: 8000,
      });
      const parsed = JSON.parse(out) as { sandboxes?: Array<{ name?: string; phase?: string }> };
      const match = parsed.sandboxes?.find(s => s.name === this.name);
      return match?.phase || null;
    } catch {
      try {
        const out = execFileSync('openshell', ['sandbox', 'get', this.name], {
          encoding: 'utf8',
          stdio: ['ignore', 'pipe', 'ignore'],
          timeout: 8000,
        });
        const phaseMatch = /^\s*Phase:\s*(\S+)/m.exec(out);
        return phaseMatch ? phaseMatch[1] : null;
      } catch {
        return null;
      }
    }
  }

  public stop(): boolean {
    try {
      execFileSync('openshell', ['sandbox', 'stop', this.name], {
        stdio: ['ignore', 'ignore', 'ignore'],
        timeout: 25000,
      });
      logDebug(`Stopped sandbox ${this.name} (hibernated)`);
      return true;
    } catch (err) {
      logDebug(`Failed to stop sandbox ${this.name}: ${err}`);
      return false;
    }
  }

  public start(): boolean {
    try {
      execFileSync('openshell', ['sandbox', 'start', this.name], {
        stdio: ['ignore', 'ignore', 'ignore'],
        timeout: 35000,
      });
      logDebug(`Started sandbox ${this.name} (resumed)`);
      return true;
    } catch (err) {
      logDebug(`Failed to start sandbox ${this.name}: ${err}`);
      return false;
    }
  }

  public getRuntimeContainerId(): string | null {
    try {
      const out = execFileSync('docker', [
        'ps',
        '--filter', `name=openshell-${this.name}-runtime`,
        '--format', '{{.ID}}',
      ], { encoding: 'utf-8', stdio: ['ignore', 'pipe', 'ignore'] });
      return out.trim() || null;
    } catch {
      return null;
    }
  }

  public pause(): void {
    const id = this.getRuntimeContainerId();
    if (id) {
      try {
        execFileSync('docker', ['pause', id], { stdio: ['ignore', 'ignore', 'ignore'] });
        logDebug(`Paused container ${id} for sandbox ${this.name}`);
      } catch {}
    }
  }

  public unpause(): void {
    const id = this.getRuntimeContainerId();
    if (id) {
      try {
        execFileSync('docker', ['unpause', id], { stdio: ['ignore', 'ignore', 'ignore'] });
        logDebug(`Resumed container ${id} for sandbox ${this.name}`);
      } catch {}
    }
  }
}

/** Download only approved workspace paths when the bridge is running scoped. */
export function syncWorkspaceBack(
  sandboxName: string,
  projectRoot: string,
  projectName: string,
  workspaceWritePaths?: string[] | null
): void {
  const relativePaths = workspaceWritePaths == null ? [null] : workspaceWritePaths;
  for (const relative of relativePaths) {
    const sandboxPath = relative
      ? path.posix.join('/sandbox', projectName, ...relative.split(path.sep))
      : path.posix.join('/sandbox', projectName);
    const hostPath = relative ? path.join(projectRoot, relative) : projectRoot;
    try {
      execFileSync('openshell', ['sandbox', 'download', sandboxName, sandboxPath, hostPath], {
        stdio: ['ignore', 'ignore', 'ignore'],
      });
    } catch (err) {
      logDebug(`Scoped workspace sync failed for ${relative ?? projectName}: ${err}`);
    }
  }
}
