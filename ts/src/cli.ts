#!/usr/bin/env node
import path from 'node:path';
import type { AgentAdapter, AgentType } from './types.js';
import { ClaudeAdapter } from './agents/claude.js';
import { CodexAdapter } from './agents/codex.js';
import { AntigravityAdapter } from './agents/antigravity.js';
import { runSandboxSession } from './runner.js';
import { runAgyChatDaemon, runAgyChatExec, runAgyPolicyAdd } from './agy-chat-sandbox.js';

function getAdapter(target: string): AgentAdapter {
  switch (target.toLowerCase()) {
    case 'claude':
    case 'claude-box':
    case 'claude-code':
      return new ClaudeAdapter();
    case 'codex':
    case 'codex-box':
      return new CodexAdapter();
    case 'agy':
    case 'agy-box':
    case 'antigravity':
      return new AntigravityAdapter();
    default:
      console.error(`Unknown agent: "${target}". Supported: claude, codex, agy`);
      process.exit(1);
  }
}

async function main(): Promise<void> {
  const binaryName = path.basename(process.argv[1]);
  let agentTarget: string;
  let forwardedArgs: string[];

  if (binaryName.includes('agent-box')) {
    agentTarget = process.argv[2] || '';
    if (agentTarget === 'agy-chat-daemon') {
      const sessionDir = process.argv[3] || '';
      const projectRoot = process.argv[4] || process.cwd();
      const harnessPid = Number(process.argv[5] || '0');
      const code = await runAgyChatDaemon(sessionDir, projectRoot, harnessPid);
      process.exit(code);
    }
    if (agentTarget === 'agy-chat-exec') {
      const shellName = process.argv[3] || 'zsh';
      const commandLine = process.argv[4] || '';
      const code = await runAgyChatExec(shellName, commandLine);
      process.exit(code);
    }
    if (agentTarget === 'policy-add' || agentTarget === 'openshell-l7-allow') {
      const code = await runAgyPolicyAdd(process.argv.slice(3));
      process.exit(code);
    }
    if (!agentTarget || agentTarget.startsWith('-')) {
      console.log('Usage: agent-box <claude|codex|agy> [options...]');
      process.exit(0);
    }
    forwardedArgs = process.argv.slice(3);
  } else {
    // Invoked directly via symlink (e.g. claude-box, agy-box, codex-box)
    agentTarget = binaryName;
    forwardedArgs = process.argv.slice(2);
  }

  const adapter = getAdapter(agentTarget);
  const exitCode = await runSandboxSession(adapter, forwardedArgs);
  process.exit(exitCode);
}

main().catch((err) => {
  console.error('Fatal error running sandbox session:', err);
  process.exit(1);
});
