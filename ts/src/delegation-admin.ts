#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { revokeGrant, writeGrant } from './delegation.js';

function option(args: string[], name: string): string | null {
  const i = args.indexOf(name);
  return i < 0 ? null : args[i + 1] || null;
}
function usage(): never {
  console.error('Usage: orca-delegation grant --terminal <handle> --workspace <id:repo-id::path> [--agents codex,claude] [--max-workers 2] [--max-depth 1]');
  console.error('       orca-delegation revoke --terminal <handle>');
  process.exit(64);
}
const [command, ...args] = process.argv.slice(2);
const terminal = option(args, '--terminal');
if (!terminal) usage();
if (command === 'revoke') {
  revokeGrant(terminal);
  console.log(`Revoked delegation for ${terminal}`);
} else if (command === 'grant') {
  const workspace = option(args, '--workspace');
  if (!workspace?.startsWith('id:')) usage();
  const agents = (option(args, '--agents') || 'codex').split(',');
  const maxWorkers = Number(option(args, '--max-workers') || '2');
  const maxDepth = Number(option(args, '--max-depth') || '1');
  // The workspace selector must resolve before a grant can be written.
  try {
    execFileSync('orca', ['worktree', 'show', '--worktree', workspace, '--json'], { stdio: ['ignore', 'pipe', 'pipe'], timeout: 15000 });
  } catch { throw new Error(`Orca cannot resolve workspace ${workspace}`); }
  const listed = JSON.parse(execFileSync('orca', ['terminal', 'list', '--worktree', workspace, '--json'], { encoding: 'utf8', timeout: 15000 }));
  const selected = listed.result?.terminals?.find((item: { handle?: string }) => item.handle === terminal);
  if (!selected || !['codex', 'claude', 'antigravity', 'agy'].includes(selected.agentIdentity)) throw new Error(`Terminal ${terminal} is not a supported agent in ${workspace}`);
  writeGrant({ terminal, workspace, agents: agents as ('codex' | 'claude' | 'antigravity' | 'agy')[], maxWorkers, maxDepth, depth: 0 });
  console.log(`Granted ${terminal} access to ${workspace}: agents=${agents.join(',')} maxWorkers=${maxWorkers} maxDepth=${maxDepth}`);
} else usage();
