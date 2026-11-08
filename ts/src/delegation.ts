import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync, spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import readline from 'node:readline';
import { logDebug } from './config.js';

type Agent = 'codex' | 'claude' | 'antigravity' | 'agy';
type Grant = { terminal: string; workspace: string; agents: Agent[]; maxWorkers: number; maxDepth: number; depth: number };
type Request = { id: string; argv: string[] };
type Reply = { code: number; stdout: string; stderr: string };
const MAX_REQUEST = 65536;
const ID = /^[a-f0-9-]{36}$/;
const terminalKey = (terminal: string): string => crypto.createHash('sha256').update(terminal).digest('hex');
export const delegationHome = (): string => process.env.OPENSHELL_BRIDGE_DELEGATION_HOME || path.join(os.homedir(), '.agents', 'orca-openshell-delegation');
const grantPath = (terminal: string): string => path.join(delegationHome(), 'grants', `${terminalKey(terminal)}.json`);
const markerPath = (terminal: string): string => path.join(delegationHome(), 'launches', `${terminalKey(terminal)}.json`);

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
function orca(args: string[], cwd: string, input?: string): Reply {
  try {
    const stdout = execFileSync('orca', args, { cwd, input, encoding: 'utf8', timeout: 180000, maxBuffer: 2_000_000, stdio: ['pipe', 'pipe', 'pipe'] });
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
    const listed = JSON.parse(execFileSync('openshell', ['sandbox', 'list', '-o', 'json'], { encoding: 'utf8', timeout: 15000 }));
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
  get sandboxDir(): string { return this.dir; }
  start(): void {
    execFileSync('openshell', ['sandbox', 'exec', '--name', this.sandbox, '--no-tty', '--no-login-shell', '--', 'sh', '-c', 'mkdir -m 700 "$1" && mkfifo -m 600 "$1/requests"', 'sh', this.dir], { timeout: 15000 });
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
    if (command === 'worker-start') return this.workerStart(args, grant);
    if (command === 'worker-show' && allowedFlags(args, ['--dispatch'], ['--full']) && value(args, '--dispatch')) {
      return orca(['orchestration', 'worker-show', ...args, '--json'], this.cwd);
    }
    if (command === 'worker-read' && allowedFlags(args, ['--dispatch', '--source', '--cursor', '--limit'], ['--full']) && value(args, '--dispatch')) {
      return orca(['orchestration', 'worker-read', ...args, '--json'], this.cwd);
    }
    if (command === 'check' && allowedFlags(args, ['--timeout-ms', '--types'], ['--peek', '--all', '--unread', '--wait'])) {
      return orca(['orchestration', 'check', ...args, '--terminal', this.terminal, '--json'], this.cwd);
    }
    if (command === 'reply' && allowedFlags(args, ['--id', '--body']) && value(args, '--id') && value(args, '--body')) {
      return orca(['orchestration', 'reply', ...args, '--from', this.terminal, '--json'], this.cwd);
    }
    if (command === 'send' && allowedFlags(args, ['--subject', '--body', '--to', '--type', '--task-id', '--dispatch-id', '--outcome']) && value(args, '--subject') && value(args, '--body')) {
      const type = value(args, '--type');
      if (type && !['status', 'question', 'heartbeat', 'worker_done'].includes(type)) return { code: 64, stdout: '', stderr: 'Message type denied\n' };
      if (type === 'worker_done' && !['succeeded', 'failed'].includes(value(args, '--outcome') || '')) return { code: 64, stdout: '', stderr: 'Invalid worker outcome\n' };
      return orca(['orchestration', 'send', ...args, '--from', this.terminal, '--json'], this.cwd);
    }
    return { code: 64, stdout: '', stderr: 'Unsupported delegated Orca command\n' };
  }
  private workerStart(args: string[], grant: Grant): Reply {
    if (!allowedFlags(args, ['--spec', '--task-title', '--agent', '--worktree', '--model', '--effort'], ['--keep-open'])) return { code: 64, stdout: '', stderr: 'Unsupported worker-start option\n' };
    const requestedWorkspace = value(args, '--worktree');
    if (requestedWorkspace && requestedWorkspace !== 'current') return { code: 77, stdout: '', stderr: 'Only the granted current workspace is allowed\n' };
    const spec = value(args, '--spec');
    if (!spec || spec.length > 32000) return { code: 64, stdout: '', stderr: 'A bounded --spec is required\n' };
    const model = value(args, '--model');
    const effort = value(args, '--effort');
    if (effort && !model) return { code: 64, stdout: '', stderr: '--effort requires --model\n' };
    const agent = value(args, '--agent') || grant.agents[0];
    if (!grant.agents.includes(agent as Agent)) return { code: 77, stdout: '', stderr: 'Agent is not allowed by the delegation grant\n' };
    if (grant.depth >= grant.maxDepth || this.attempts >= grant.maxWorkers) return { code: 77, stdout: '', stderr: 'Worker or nesting limit reached\n' };
    this.attempts++;
    const launchedAt = Date.now();
    const launchArgs = ['agent', 'launch', '--agent', agent, '--surface', 'terminal', '--worktree', grant.workspace];
    if (model) launchArgs.push('--model', model);
    if (effort) launchArgs.push('--effort', effort);
    launchArgs.push('--json');
    const launched = orca(launchArgs, this.cwd);
    if (launched.code) return launched;
    const handle = parseJson(launched)?.result?.launch?.outcome?.handle || parseJson(launched)?.result?.outcome?.handle;
    if (typeof handle !== 'string' || !handle) return { code: 1, stdout: launched.stdout, stderr: 'No terminal handle in agent launch receipt; manual recovery required\n' };
    let marker = readLaunch(handle);
    for (let i = 0; i < 60 && (!marker || marker.at < launchedAt); i++) {
      execFileSync('sleep', ['1']);
      marker = readLaunch(handle);
    }
    const coordinatorId = gatewaySandbox(this.sandbox);
    const workerId = marker ? gatewaySandbox(marker.sandbox) : null;
    if (!marker || marker.at < launchedAt || marker.workspace !== this.workspace || marker.sandbox === this.sandbox || !coordinatorId || !workerId || workerId === coordinatorId) {
      const close = orca(['terminal', 'close', '--terminal', handle, '--json'], this.cwd);
      return { code: 1, stdout: launched.stdout, stderr: `Worker terminal ${handle} lacks verified, distinct OpenShell sandbox; launch refused. Close result: ${close.code === 0 ? 'closed' : 'unknown; inspect manually'}\n` };
    }
    writeGrant({ terminal: handle, workspace: grant.workspace, agents: grant.agents, maxWorkers: grant.maxWorkers, depth: grant.depth + 1, maxDepth: grant.maxDepth });
    orca(['terminal', 'wait', '--terminal', handle, '--for', 'tui-idle', '--timeout-ms', '15000', '--json'], this.cwd);
    const startArgs = ['orchestration', 'worker-start', '--spec', spec, '--terminal', handle, '--worktree', grant.workspace, '--from', this.terminal];
    if (value(args, '--task-title')) startArgs.push('--task-title', value(args, '--task-title')!);
    if (args.includes('--keep-open')) startArgs.push('--keep-open');
    startArgs.push('--json');
    const started = orca(startArgs, this.cwd);
    if (started.code !== 0) {
      revokeGrant(handle);
      const dispatchId = parseJson(started)?.result?.dispatchId;
      if (typeof dispatchId === 'string') {
        orca(['orchestration', 'worker-release', '--dispatch', dispatchId, '--json'], this.cwd);
      }
      const close = orca(['terminal', 'close', '--terminal', handle, '--json'], this.cwd);
      started.stderr += `OpenShell worker startup failed; pre-created terminal ${handle} close result: ${close.code === 0 ? 'closed' : 'failed; inspect manually'}.\n`;
    }
    return started;
  }
}
