import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFileSync, spawn } from 'node:child_process';
import type { OpenShellPolicy } from './types.js';
import { logDebug } from './config.js';

export class OpenShellSandbox {
  constructor(public readonly name: string) {}

  public static create(
    name: string,
    image: string,
    providers: string[],
    policy: OpenShellPolicy | null,
    uploads: Array<{ source: string; destination: string }> = []
  ): OpenShellSandbox {
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

  public delete(detached = false): void {
    try {
      if (detached) {
        const child = spawn('openshell', ['sandbox', 'delete', this.name], {
          detached: true,
          stdio: 'ignore',
        });
        child.unref();
        logDebug(`Scheduled detached deletion for sandbox ${this.name}`);
      } else {
        execFileSync('openshell', ['sandbox', 'delete', this.name], {
          stdio: ['ignore', 'ignore', 'ignore'],
          timeout: 15000,
        });
        logDebug(`Deleted sandbox ${this.name}`);
      }
    } catch (err) {
      logDebug(`Failed to delete sandbox ${this.name}: ${err}`);
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
