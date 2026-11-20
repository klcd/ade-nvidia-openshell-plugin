import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync, spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import readline from 'node:readline';
import { logDebug } from './config.js';
import { recordWorktreeParentPath, removeWorktreeParentPath } from '../../orca-plugin/src/state/sandbox-mode.js';
import type { OpenShellPolicy } from './types.js';
import {
  installTempWorktreePolicy,
  removeTempWorktreePolicy,
  resolveSubagentCombinedPolicy,
  type WorkspaceFileScope,
} from './sandbox-scope.js';

type Agent = 'codex' | 'claude' | 'antigravity' | 'agy';
type Grant = {
  terminal: string;
  workspace: string;
  agents: Agent[];
  maxWorkers: number;
  maxDepth: number;
  depth: number;
  allowNewWorktree?: boolean;
  allowDynamicPolicies?: boolean;
  allowedEgressHosts?: string[];
  fileScope?: WorkspaceFileScope;
  openshellPolicy?: OpenShellPolicy;
};
export type StoredWorkerScope = {
  terminal: string;
  workspace: string;
  projectRoot: string;
  fileScope: WorkspaceFileScope | null;
  openshellPolicy?: OpenShellPolicy | null;
  tempPolicyFilePath?: string | null;
  tempPolicyCreatedDirs?: string[];
  at: number;
};
type PendingWorkerScope = {
  id: string;
  workspace: string;
  projectRoot: string;
  parentProjectRoot?: string;
  agent: string;
  fileScope: WorkspaceFileScope | null;
  openshellPolicy?: OpenShellPolicy | null;
  tempPolicyFilePath?: string | null;
  tempPolicyCreatedDirs?: string[];
  pendingGrant?: Omit<Grant, 'terminal'>;
  at: number;
};
type ClaimedWorkerScope = {
  id: string;
  terminal: string;
  workspace: string;
  at: number;
};
type Request = { id: string; argv: string[] };
type Reply = { code: number; stdout: string; stderr: string };
const MAX_REQUEST = 65536;
const ID = /^[a-f0-9-]{36}$/;
const terminalKey = (terminal: string): string => crypto.createHash('sha256').update(terminal).digest('hex');
export const delegationHome = (): string => process.env.OPENSHELL_BRIDGE_DELEGATION_HOME || path.join(os.homedir(), '.agents', 'orca-openshell-delegation');
const grantPath = (terminal: string): string => path.join(delegationHome(), 'grants', `${terminalKey(terminal)}.json`);
const markerPath = (terminal: string): string => path.join(delegationHome(), 'launches', `${terminalKey(terminal)}.json`);
const scopePath = (terminal: string): string => path.join(delegationHome(), 'scopes', `${terminalKey(terminal)}.json`);
const pendingScopeDir = (): string => path.join(delegationHome(), 'pending-scopes');
const pendingScopePath = (id: string): string => path.join(pendingScopeDir(), `${id}.json`);
const claimedScopeDir = (): string => path.join(delegationHome(), 'claimed-scopes');
const claimedScopePath = (id: string): string => path.join(claimedScopeDir(), `${id}.json`);

function privateDir(dir: string): void { fs.mkdirSync(dir, { recursive: true, mode: 0o700 }); fs.chmodSync(dir, 0o700); }
function writePrivate(file: string, data: unknown): void {
  privateDir(path.dirname(file));
  const temp = `${file}.${process.pid}.${crypto.randomUUID()}`;
  fs.writeFileSync(temp, JSON.stringify(data), { mode: 0o600 });
  fs.renameSync(temp, file);
}
export function writeGrant(grant: Grant): void {
  const allowedAgents: Agent[] = ['codex', 'claude', 'antigravity', 'agy'];
  if (!grant.terminal || !grant.workspace.startsWith('id:') ||
      !grant.agents.length || grant.agents.some(a => !allowedAgents.includes(a)) ||
      !Number.isInteger(grant.maxWorkers) || grant.maxWorkers < 1 || grant.maxWorkers > 32 ||
      !Number.isInteger(grant.depth) || !Number.isInteger(grant.maxDepth) ||
      grant.depth < 0 || grant.maxDepth < grant.depth || grant.maxDepth > 8) throw new Error('Invalid delegation grant');
  writePrivate(grantPath(grant.terminal), grant);
}
export function revokeGrant(terminal: string): void {
  if (terminal) try { fs.unlinkSync(grantPath(terminal)); } catch {}
}
export function readGrant(terminal: string, workspace: string): Grant | null {
  try {
    const grant = JSON.parse(fs.readFileSync(grantPath(terminal), 'utf8')) as Grant;
    if (grant.terminal !== terminal || grant.workspace !== `id:${workspace}`) return null;
    if (!Array.isArray(grant.agents) || !Number.isInteger(grant.maxWorkers) || !Number.isInteger(grant.depth) || !Number.isInteger(grant.maxDepth)) return null;
    return grant;
  } catch { return null; }
}
export function writeWorkerScope(terminal: string, scope: Omit<StoredWorkerScope, 'terminal'>): void {
  if (!terminal) return;
  writePrivate(scopePath(terminal), { ...scope, terminal });
}
export function readWorkerScope(terminal: string, workspace?: string): StoredWorkerScope | null {
  if (!terminal) return null;
  try {
    const data = JSON.parse(fs.readFileSync(scopePath(terminal), 'utf8')) as StoredWorkerScope;
    if (data.terminal !== terminal) return null;
    if (workspace && data.workspace !== `id:${workspace}` && data.workspace !== workspace) return null;
    if (!data.fileScope && !data.openshellPolicy && !data.tempPolicyFilePath) return null;
    return data;
  } catch { return null; }
}
export function deleteWorkerScope(terminal: string): void {
  if (terminal) try { fs.unlinkSync(scopePath(terminal)); } catch {}
}
export function cleanupWorkerScope(terminal: string): void {
  if (!terminal) return;
  const scope = readWorkerScope(terminal);
  if (scope?.tempPolicyFilePath) {
    removeTempWorktreePolicy(scope.tempPolicyFilePath, scope.tempPolicyCreatedDirs);
  }
  deleteWorkerScope(terminal);
}
function writePendingScope(scope: Omit<PendingWorkerScope, 'id' | 'at'>): string {
  const id = crypto.randomUUID();
  writePrivate(pendingScopePath(id), { ...scope, id, at: Date.now() });
  return id;
}
function deletePendingScope(id: string): void {
  if (id) try { fs.unlinkSync(pendingScopePath(id)); } catch {}
}
function readClaimedScope(id: string): ClaimedWorkerScope | null {
  if (!id) return null;
  try {
    return JSON.parse(fs.readFileSync(claimedScopePath(id), 'utf8')) as ClaimedWorkerScope;
  } catch { return null; }
}
function deleteClaimedScope(id: string): void {
  if (id) try { fs.unlinkSync(claimedScopePath(id)); } catch {}
}
function agentsMatch(pendingAgent: string, runtimeAgent: string): boolean {
  if (pendingAgent === runtimeAgent) return true;
  const agy = new Set(['antigravity', 'agy']);
  return agy.has(pendingAgent) && agy.has(runtimeAgent);
}
export function claimPendingDelegationScope(terminalId: string, workspaceId: string, agent: string): StoredWorkerScope | null {
  if (!terminalId || !workspaceId || !agent) return null;
  const dir = pendingScopeDir();
  if (!fs.existsSync(dir)) return null;
  const expectedWs = workspaceId.startsWith('id:') ? workspaceId : `id:${workspaceId}`;
  const now = Date.now();
  let files: string[];
  try {
    files = fs.readdirSync(dir).filter(f => f.endsWith('.json')).sort();
  } catch {
    return null;
  }
  for (const file of files) {
    const full = path.join(dir, file);
    const claiming = `${full}.${process.pid}.${crypto.randomUUID()}.claiming`;
    try {
      const data = JSON.parse(fs.readFileSync(full, 'utf8')) as PendingWorkerScope;
      if (typeof data.at !== 'number' || now - data.at > 60_000) {
        try { fs.unlinkSync(full); } catch {}
        continue;
      }
      if (data.workspace === expectedWs && agentsMatch(data.agent, agent)) {
        try {
          fs.renameSync(full, claiming);
        } catch {
          continue;
        }
        let stored: StoredWorkerScope | null = null;
        if (data.fileScope || data.openshellPolicy || data.tempPolicyFilePath) {
          const record: Omit<StoredWorkerScope, 'terminal'> = {
            workspace: data.workspace,
            projectRoot: data.projectRoot,
            fileScope: data.fileScope ?? null,
            ...(data.openshellPolicy ? { openshellPolicy: data.openshellPolicy } : {}),
            ...(data.tempPolicyFilePath ? { tempPolicyFilePath: data.tempPolicyFilePath } : {}),
            ...(data.tempPolicyCreatedDirs ? { tempPolicyCreatedDirs: data.tempPolicyCreatedDirs } : {}),
            at: now,
          };
          writeWorkerScope(terminalId, record);
          stored = { ...record, terminal: terminalId };
        }
        if (data.pendingGrant) {
          try {
            writeGrant({ ...data.pendingGrant, terminal: terminalId });
          } catch {}
        }
        if (data.id) {
          writePrivate(claimedScopePath(data.id), { id: data.id, terminal: terminalId, workspace: expectedWs, at: now });
        }
        try { fs.unlinkSync(claiming); } catch {}
        return stored;
      }
    } catch {}
  }
  return null;
}
function promotePendingScope(id: string, terminal: string): void {
  if (!id || !terminal) return;
  try {
    const raw = fs.readFileSync(pendingScopePath(id), 'utf8');
    const data = JSON.parse(raw) as PendingWorkerScope;
    if (data.fileScope || data.openshellPolicy || data.tempPolicyFilePath) {
      writeWorkerScope(terminal, {
        workspace: data.workspace,
        projectRoot: data.projectRoot,
        fileScope: data.fileScope ?? null,
        ...(data.openshellPolicy ? { openshellPolicy: data.openshellPolicy } : {}),
        ...(data.tempPolicyFilePath ? { tempPolicyFilePath: data.tempPolicyFilePath } : {}),
        ...(data.tempPolicyCreatedDirs ? { tempPolicyCreatedDirs: data.tempPolicyCreatedDirs } : {}),
        at: Date.now(),
      });
    }
    if (data.pendingGrant) {
      try {
        writeGrant({ ...data.pendingGrant, terminal });
      } catch {}
    }
    writePrivate(claimedScopePath(id), { id, terminal, workspace: data.workspace, at: Date.now() });
    try { fs.unlinkSync(pendingScopePath(id)); } catch {}
  } catch {
    // Already claimed and deleted by agent.launch.before hook or runner
  }
}
export function recordLaunch(terminal: string, workspace: string, sandbox: string): void {
  if (!terminal || !workspace) return;
  writePrivate(markerPath(terminal), { terminal, workspace, sandbox, at: Date.now() });
}
export function forgetLaunch(terminal: string): void {
  if (terminal) try { fs.unlinkSync(markerPath(terminal)); } catch {}
}
function readLaunch(terminal: string): { terminal: string; workspace: string; sandbox: string; at: number } | null {
  try { return JSON.parse(fs.readFileSync(markerPath(terminal), 'utf8')); } catch { return null; }
}
function resolveBin(name: string): string {
  for (const dir of (process.env.PATH || '').split(path.delimiter)) {
    if (!dir) continue;
    const candidate = path.join(dir, name);
    try {
      fs.accessSync(candidate, fs.constants.X_OK);
      if (fs.statSync(candidate).isFile()) return candidate;
    } catch {}
  }
  return name;
}
function orca(args: string[], cwd: string, input?: string, keepAmbientSessionEnv = false): Reply {
  try {
    let env: NodeJS.ProcessEnv = process.env;
    if (!keepAmbientSessionEnv && (process.env.ORCA_AGENT_SESSION_ID || process.env.ORCA_AGENT_SESSION_SPAWN_TOKEN)) {
      const copy = { ...process.env };
      delete copy.ORCA_AGENT_SESSION_ID;
      delete copy.ORCA_AGENT_SESSION_SPAWN_TOKEN;
      env = copy;
    }
    const stdout = execFileSync(resolveBin('orca'), args, { cwd, input, env, encoding: 'utf8', timeout: 180000, maxBuffer: 2_000_000, stdio: ['pipe', 'pipe', 'pipe'] });
    return { code: 0, stdout, stderr: '' };
  } catch (err) {
    const e = err as { status?: number; stdout?: Buffer | string; stderr?: Buffer | string };
    return { code: e.status ?? 1, stdout: String(e.stdout || ''), stderr: String(e.stderr || err).slice(0, 8000) };
  }
}
function value(args: string[], flag: string): string | null {
  const i = args.indexOf(flag);
  return i >= 0 && i + 1 < args.length ? args[i + 1] : null;
}
function allowedFlags(args: string[], values: string[], switches: string[] = []): boolean {
  const seen = new Set<string>();
  for (let i = 0; i < args.length; i++) {
    if (seen.has(args[i])) return false;
    seen.add(args[i]);
    if (values.includes(args[i])) { if (++i >= args.length || args[i].startsWith('--')) return false; }
    else if (!switches.includes(args[i])) return false;
  }
  return true;
}
function parseJson(reply: Reply): any {
  try { return JSON.parse(reply.stdout); } catch { return null; }
}
function gatewaySandbox(name: string): string | null {
  try {
    const listed = JSON.parse(execFileSync(resolveBin('openshell'), ['sandbox', 'list', '-o', 'json'], { env: process.env, encoding: 'utf8', timeout: 15000 }));
    const row = listed.sandboxes?.find((s: any) => s.name === name);
    return row?.phase === 'Ready' ? row?.id || null : null;
  } catch { return null; }
}

export class DelegationBroker {
  private reader: ChildProcessWithoutNullStreams | null = null;
  private attempts = 0;
  private readonly dir: string;
  constructor(private readonly sandbox: string, private readonly terminal: string, private readonly workspace: string, private readonly cwd: string) {
    this.dir = `/tmp/orca-delegate-${crypto.randomUUID()}`;
  }
  private get isAmbientAgentSession(): boolean {
    const sid = process.env.ORCA_AGENT_SESSION_ID;
    return Boolean(sid && this.terminal === `structured-agent-session-${sid}`);
  }
  get sandboxDir(): string { return this.dir; }
  start(): void {
    this.stop();
    execFileSync('openshell', ['sandbox', 'exec', '--name', this.sandbox, '--no-tty', '--no-login-shell', '--', 'sh', '-c', 'rm -rf "$1" && mkdir -m 700 "$1" && mkfifo -m 600 "$1/requests"', 'sh', this.dir], { timeout: 15000 });
    this.reader = spawn('openshell', ['sandbox', 'exec', '--name', this.sandbox, '--no-tty', '--no-login-shell', '--', 'sh', '-c', 'while :; do cat "$1"; done', 'sh', `${this.dir}/requests`], { stdio: ['pipe', 'pipe', 'pipe'] });
    this.reader.stdin.end();
    this.reader.on('error', error => logDebug(`Delegation reader failed: ${error}`));
    this.reader.stderr.on('data', chunk => logDebug(`Delegation reader: ${String(chunk).slice(0, 500)}`));
    const lines = readline.createInterface({ input: this.reader.stdout });
    lines.on('line', line => { void this.handleLine(line); });
  }
  stop(): void { this.reader?.kill('SIGTERM'); this.reader = null; }
  private async handleLine(line: string): Promise<void> {
    let request: Request;
    try {
      if (line.length > MAX_REQUEST) throw new Error('Request too large');
      request = JSON.parse(line);
      if (!ID.test(request.id) || !Array.isArray(request.argv) || request.argv.some(x => typeof x !== 'string')) throw new Error('Invalid request');
    } catch { return; }
    const reply = this.dispatch(request.argv);
    const target = `${this.dir}/${request.id}`;
    const child = spawn('openshell', ['sandbox', 'exec', '--name', this.sandbox, '--no-tty', '--no-login-shell', '--timeout', '15', '--', 'sh', '-c', 'cat > "$1"', 'sh', target], { stdio: ['pipe', 'ignore', 'pipe'] });
    child.stdin.end(JSON.stringify(reply));
    child.on('error', error => logDebug(`Delegation reply failed: ${error}`));
    child.stderr.on('data', chunk => logDebug(`Delegation reply: ${String(chunk).slice(0, 500)}`));
  }
  dispatch(argv: string[]): Reply {
    const grant = readGrant(this.terminal, this.workspace);
    if (!grant) return { code: 77, stdout: '', stderr: 'Orca delegation is not granted for this terminal and workspace\n' };
    if (argv[0] !== 'orchestration') return { code: 64, stdout: '', stderr: 'Only Orca orchestration commands are delegated\n' };
    const command = argv[1], args = argv.slice(2).filter(x => x !== '--json');
    if (args.includes('--from') || args.includes('--terminal') || args.includes('--environment') || args.includes('--pairing-code') || args.includes('--on')) return { code: 64, stdout: '', stderr: 'Caller identity and host placement are fixed by the bridge\n' };
    const useAmbientSession = this.isAmbientAgentSession;
    if (command === 'worker-start') return this.workerStart(args, grant);
    if (command === 'worker-show' && allowedFlags(args, ['--dispatch'], ['--full']) && value(args, '--dispatch')) {
      return orca(['orchestration', 'worker-show', ...args, '--json'], this.cwd, undefined, useAmbientSession);
    }
    if (command === 'worker-read' && allowedFlags(args, ['--dispatch', '--source', '--cursor', '--limit'], ['--full']) && value(args, '--dispatch')) {
      return orca(['orchestration', 'worker-read', ...args, '--json'], this.cwd, undefined, useAmbientSession);
    }
    if (command === 'check' && allowedFlags(args, ['--timeout-ms', '--types'], ['--peek', '--all', '--unread', '--wait'])) {
      const cmdArgs = ['orchestration', 'check', ...args, ...(useAmbientSession ? [] : ['--terminal', this.terminal]), '--json'];
      return orca(cmdArgs, this.cwd, undefined, useAmbientSession);
    }
    if (command === 'reply' && allowedFlags(args, ['--id', '--body']) && value(args, '--id') && value(args, '--body')) {
      const cmdArgs = ['orchestration', 'reply', ...args, ...(useAmbientSession ? [] : ['--from', this.terminal]), '--json'];
      return orca(cmdArgs, this.cwd, undefined, useAmbientSession);
    }
    if (command === 'send' && allowedFlags(args, ['--subject', '--body', '--to', '--type', '--task-id', '--dispatch-id', '--outcome']) && value(args, '--subject') && value(args, '--body')) {
      const type = value(args, '--type');
      if (type && !['status', 'question', 'heartbeat', 'worker_done'].includes(type)) return { code: 64, stdout: '', stderr: 'Message type denied\n' };
      if (type === 'worker_done' && !['succeeded', 'failed'].includes(value(args, '--outcome') || '')) return { code: 64, stdout: '', stderr: 'Invalid worker outcome\n' };
      const cmdArgs = ['orchestration', 'send', ...args, ...(useAmbientSession ? [] : ['--from', this.terminal]), '--json'];
      return orca(cmdArgs, this.cwd, undefined, useAmbientSession);
    }
    return { code: 64, stdout: '', stderr: 'Unsupported delegated Orca command\n' };
  }
  private workerStart(args: string[], grant: Grant): Reply {
    if (!allowedFlags(
      args,
      ['--spec', '--task-title', '--agent', '--worktree', '--name', '--base-branch', '--setup', '--model', '--effort', '--read-paths', '--write-paths', '--openshell-policy'],
      ['--keep-open']
    )) {
      return { code: 64, stdout: '', stderr: 'Unsupported worker-start option\n' };
    }
    const requestedWorkspace = value(args, '--worktree') || 'current';
    if (requestedWorkspace !== 'current' && requestedWorkspace !== 'new-child') {
      return { code: 77, stdout: '', stderr: 'Only current or new-child worktree placement is allowed\n' };
    }
    const isNewChild = requestedWorkspace === 'new-child';
    if (isNewChild && grant.allowNewWorktree === false) {
      return { code: 77, stdout: '', stderr: 'Creating child worktrees is disabled by the delegation grant\n' };
    }
    const worktreeName = value(args, '--name');
    const baseBranch = value(args, '--base-branch');
    const setupMode = value(args, '--setup');
    if (!isNewChild && (worktreeName || baseBranch || setupMode)) {
      return { code: 64, stdout: '', stderr: '--name, --base-branch, and --setup require --worktree new-child\n' };
    }
    if (worktreeName && !/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$/.test(worktreeName)) {
      return { code: 64, stdout: '', stderr: 'Invalid --name for child worktree\n' };
    }
    if (baseBranch && (!/^[a-zA-Z0-9._/-]{1,128}$/.test(baseBranch) || baseBranch.startsWith('-') || baseBranch.includes('..'))) {
      return { code: 64, stdout: '', stderr: 'Invalid --base-branch ref\n' };
    }
    if (setupMode && !['run', 'skip', 'inherit'].includes(setupMode)) {
      return { code: 64, stdout: '', stderr: '--setup must be one of run, skip, or inherit\n' };
    }

    const spec = value(args, '--spec');
    if (!spec || spec.length > 32000) return { code: 64, stdout: '', stderr: 'A bounded --spec is required\n' };
    const model = value(args, '--model');
    const effort = value(args, '--effort');
    if (effort && !model) return { code: 64, stdout: '', stderr: '--effort requires --model\n' };
    const agent = value(args, '--agent') || grant.agents[0];
    if (!grant.agents.includes(agent as Agent)) return { code: 77, stdout: '', stderr: 'Agent is not allowed by the delegation grant\n' };
    if (grant.depth >= grant.maxDepth || this.attempts >= grant.maxWorkers) return { code: 77, stdout: '', stderr: 'Worker or nesting limit reached\n' };

    const existingWorkerScope = readWorkerScope(this.terminal, this.workspace);
    const parentFileScope = grant.fileScope ?? existingWorkerScope?.fileScope ?? null;
    const parentOpenShellPolicy = grant.openshellPolicy ?? existingWorkerScope?.openshellPolicy ?? null;

    let workerFileScope: WorkspaceFileScope | null = null;
    let workerOpenShellPolicy: OpenShellPolicy | null = null;
    try {
      const combined = resolveSubagentCombinedPolicy({
        projectRoot: this.cwd,
        readRaw: value(args, '--read-paths'),
        writeRaw: value(args, '--write-paths'),
        openshellPolicyRaw: value(args, '--openshell-policy'),
        parentFileScope,
        parentOpenShellPolicy,
        allowedEgressHosts: grant.allowedEgressHosts,
        allowDynamicPolicies: grant.allowDynamicPolicies,
      });
      workerFileScope = combined.fileScope;
      workerOpenShellPolicy = combined.openshellPolicy;
    } catch (err) {
      return { code: 77, stdout: '', stderr: `Invalid worker policy: ${err instanceof Error ? err.message : String(err)}\n` };
    }

    this.attempts++;

    let targetWorkspaceSelector = grant.workspace;
    let targetWorkspaceRawId = this.workspace;
    let targetProjectRoot = this.cwd;
    let createdChildWorktree = false;

    if (isNewChild) {
      const effectiveName = worktreeName || `subagent-${crypto.randomUUID().slice(0, 8)}`;
      const createArgs = ['worktree', 'create', '--name', effectiveName, '--parent-worktree', grant.workspace];
      if (baseBranch) createArgs.push('--base-branch', baseBranch);
      if (setupMode) createArgs.push('--setup', setupMode);
      createArgs.push('--json');
      const created = orca(createArgs, this.cwd);
      if (created.code !== 0) {
        return created;
      }
      const createdJson = parseJson(created);
      const wtRecord = createdJson?.result?.worktree || createdJson?.result;
      let rawId = typeof wtRecord?.id === 'string' ? wtRecord.id : '';
      let rawPath = typeof wtRecord?.path === 'string' ? wtRecord.path : '';
      if (!rawId || !rawPath) {
        const listed = orca(['worktree', 'list', '--json'], this.cwd);
        const listJson = parseJson(listed);
        const found = listJson?.result?.worktrees?.find(
          (w: { id?: string; path?: string; displayName?: string; name?: string }) =>
            (rawId && w.id === rawId) ||
            (rawPath && w.path === rawPath) ||
            w.displayName === effectiveName ||
            w.name === effectiveName
        );
        if (found?.id) rawId = found.id;
        if (found?.path) rawPath = found.path;
      }
      if (!rawId || !rawPath || !fs.existsSync(rawPath)) {
        if (rawId) {
          const sel = rawId.startsWith('id:') ? rawId : `id:${rawId}`;
          orca(['worktree', 'rm', '--worktree', sel, '--force', '--delete-branch', '--json'], this.cwd);
        }
        return { code: 1, stdout: created.stdout, stderr: 'Failed to resolve created child worktree path or id\n' };
      }
      targetWorkspaceSelector = rawId.startsWith('id:') ? rawId : `id:${rawId}`;
      targetWorkspaceRawId = targetWorkspaceSelector.slice(3);
      targetProjectRoot = rawPath;
      createdChildWorktree = true;
      if (!process.env.OPENSHELL_BRIDGE_DELEGATION_HOME || process.env.ORCA_OPENSHELL_MODE_FILE) {
        recordWorktreeParentPath(targetProjectRoot, this.cwd);
      }
    }

    let tempPolicyFilePath: string | null = null;
    let tempPolicyCreatedDirs: string[] = [];
    const rollbackNewChild = () => {
      if (tempPolicyFilePath) {
        removeTempWorktreePolicy(tempPolicyFilePath, tempPolicyCreatedDirs);
        tempPolicyFilePath = null;
      }
      if (createdChildWorktree) {
        if (!process.env.OPENSHELL_BRIDGE_DELEGATION_HOME || process.env.ORCA_OPENSHELL_MODE_FILE) {
          removeWorktreeParentPath(targetProjectRoot);
        }
        orca(['worktree', 'rm', '--worktree', targetWorkspaceSelector, '--force', '--delete-branch', '--json'], this.cwd);
      }
    };

    if (createdChildWorktree && workerOpenShellPolicy) {
      try {
        const installed = installTempWorktreePolicy(targetProjectRoot, workerOpenShellPolicy);
        tempPolicyFilePath = installed.filePath;
        tempPolicyCreatedDirs = installed.createdDirs;
      } catch (err) {
        rollbackNewChild();
        return { code: 1, stdout: '', stderr: `Failed to install temporary worktree policy: ${err instanceof Error ? err.message : String(err)}\n` };
      }
    }

    const childGrantBase: Omit<Grant, 'terminal'> = {
      workspace: targetWorkspaceSelector,
      agents: grant.agents,
      maxWorkers: grant.maxWorkers,
      depth: grant.depth + 1,
      maxDepth: grant.maxDepth,
      ...(grant.allowNewWorktree !== undefined ? { allowNewWorktree: grant.allowNewWorktree } : {}),
      ...(grant.allowDynamicPolicies !== undefined ? { allowDynamicPolicies: grant.allowDynamicPolicies } : {}),
      ...(grant.allowedEgressHosts ? { allowedEgressHosts: grant.allowedEgressHosts } : {}),
      ...(workerFileScope ? { fileScope: workerFileScope } : {}),
      ...(workerOpenShellPolicy ? { openshellPolicy: workerOpenShellPolicy } : {}),
    };

    const launchedAt = Date.now();
    const pendingScopeId = writePendingScope({
      workspace: targetWorkspaceSelector,
      projectRoot: targetProjectRoot,
      parentProjectRoot: this.cwd,
      agent,
      fileScope: workerFileScope,
      ...(workerOpenShellPolicy ? { openshellPolicy: workerOpenShellPolicy } : {}),
      ...(tempPolicyFilePath ? { tempPolicyFilePath, tempPolicyCreatedDirs } : {}),
      pendingGrant: childGrantBase,
    });

    const useAmbientSession = this.isAmbientAgentSession;
    const startArgs = [
      'orchestration',
      'worker-start',
      '--spec',
      spec,
      '--agent',
      agent,
      '--worktree',
      targetWorkspaceSelector,
      ...(useAmbientSession ? [] : ['--from', this.terminal]),
    ];
    if (model) startArgs.push('--model', model);
    if (effort) startArgs.push('--effort', effort);
    if (value(args, '--task-title')) startArgs.push('--task-title', value(args, '--task-title')!);
    if (args.includes('--keep-open')) startArgs.push('--keep-open');
    startArgs.push('--json');

    const started = orca(startArgs, targetProjectRoot, undefined, useAmbientSession);
    const startedJson = parseJson(started);
    const dispatchId = startedJson?.result?.dispatchId;
    const handle = startedJson?.result?.terminal || startedJson?.result?.handle;

    if (started.code !== 0) {
      const claimed = readClaimedScope(pendingScopeId);
      const actualTerminal = claimed?.terminal || (typeof handle === 'string' && !handle.startsWith('structworker_') ? handle : '');
      deletePendingScope(pendingScopeId);
      deleteClaimedScope(pendingScopeId);
      if (actualTerminal) {
        revokeGrant(actualTerminal);
        cleanupWorkerScope(actualTerminal);
      }
      if (typeof dispatchId === 'string') {
        orca(['orchestration', 'worker-release', '--dispatch', dispatchId, '--json'], this.cwd, undefined, useAmbientSession);
      }
      if (typeof handle === 'string' && handle.startsWith('term_')) {
        orca(['terminal', 'close', '--terminal', handle, '--json'], this.cwd);
      }
      rollbackNewChild();
      return started;
    }

    let claimed = readClaimedScope(pendingScopeId);
    let launchTerminal = claimed?.terminal || (typeof handle === 'string' && !handle.startsWith('structworker_') ? handle : '');
    let marker = launchTerminal ? readLaunch(launchTerminal) : null;
    for (let i = 0; i < 30 && (!marker || marker.at < launchedAt); i++) {
      execFileSync(resolveBin('sleep'), ['1']);
      claimed = claimed ?? readClaimedScope(pendingScopeId);
      if (!launchTerminal) {
        launchTerminal = claimed?.terminal || (typeof handle === 'string' && !handle.startsWith('structworker_') ? handle : '');
      }
      if (launchTerminal) {
        marker = readLaunch(launchTerminal);
      }
    }
    if (!claimed && launchTerminal) {
      // Fallback for mocked unit tests where agent.launch.before / runner did not run
      promotePendingScope(pendingScopeId, launchTerminal);
      if (!readGrant(launchTerminal, targetWorkspaceRawId)) {
        try { writeGrant({ terminal: launchTerminal, ...childGrantBase }); } catch {}
      }
    }

    const coordinatorId = gatewaySandbox(this.sandbox);
    const workerId = marker ? gatewaySandbox(marker.sandbox) : null;
    if (!launchTerminal || !marker || marker.at < launchedAt || marker.workspace !== targetWorkspaceRawId || marker.sandbox === this.sandbox || !coordinatorId || !workerId || workerId === coordinatorId) {
      deletePendingScope(pendingScopeId);
      deleteClaimedScope(pendingScopeId);
      if (launchTerminal) {
        revokeGrant(launchTerminal);
        cleanupWorkerScope(launchTerminal);
      }
      if (typeof dispatchId === 'string') {
        orca(['orchestration', 'worker-release', '--dispatch', dispatchId, '--json'], this.cwd, undefined, useAmbientSession);
      }
      if (typeof handle === 'string' && handle.startsWith('term_')) {
        orca(['terminal', 'close', '--terminal', handle, '--json'], this.cwd);
      }
      rollbackNewChild();
      return {
        code: 1,
        stdout: started.stdout,
        stderr: `Worker ${typeof handle === 'string' ? handle : launchTerminal || '(unknown)'} lacks verified, distinct OpenShell sandbox; launch refused.\n`,
      };
    }

    deleteClaimedScope(pendingScopeId);
    return started;
  }
}
