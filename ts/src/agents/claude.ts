import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import type { AgentAdapter, AgentType } from '../types.js';
import { USER_HOME } from '../config.js';
import { getClaudeOAuthToken } from '../keychain.js';
import { syncWorkspaceBack } from '../sandbox.js';

/**
 * Combines skills from .agents/skills into .claude/skills.
 * For Claude, .claude/skills has precedence; only skills not already inside
 * .claude/skills (compared by name) are copied from .agents/skills.
 */
export function combineSkills(targetDir: string): void {
  const claudeSkills = path.join(targetDir, '.claude', 'skills');
  const agentsSkills = path.join(targetDir, '.agents', 'skills');

  if (!fs.existsSync(agentsSkills) || !fs.statSync(agentsSkills).isDirectory()) {
    return;
  }

  fs.mkdirSync(claudeSkills, { recursive: true });
  for (const entry of fs.readdirSync(agentsSkills)) {
    const targetSkill = path.join(claudeSkills, entry);
    if (!fs.existsSync(targetSkill)) {
      const sourceSkill = path.join(agentsSkills, entry);
      fs.cpSync(sourceSkill, targetSkill, { recursive: true });
    }
  }
}

export class ClaudeAdapter implements AgentAdapter {
  public readonly type: AgentType = 'claude';
  public readonly binaryName = 'claude';
  public readonly containerImage = 'openshell-claude:latest';
  public readonly providerName = 'claude-code';

  public shouldBypassSandbox(args: string[], cwd: string): boolean {
    if (process.env.OPENSHELL_BRIDGE_REQUIRED === '1' || process.env.ORCA_OPENSHELL_REQUIRED === '1') return false;
    if (args.some(arg => ['--version', '-V', '--help', '-h'].includes(arg))) {
      return true;
    }
    if (cwd.includes('rate-limit-pty-cwd') || cwd.startsWith('/tmp') || cwd.startsWith('/private/tmp')) {
      return true;
    }
    return false;
  }

  public async getCredentials(): Promise<Record<string, string>> {
    const token = getClaudeOAuthToken();
    return token ? { CLAUDE_CODE_OAUTH_TOKEN: token } : {};
  }

  public async stageConfiguration(stageDir: string, projectRoot: string, projectName: string): Promise<void> {
    const claudeDir = path.join(stageDir, '.claude');
    fs.mkdirSync(claudeDir, { recursive: true });

    // 1. Copy essential host settings
    const hostClaude = path.join(USER_HOME, '.claude');
    if (fs.existsSync(hostClaude)) {
      for (const item of ['settings.json', 'keybindings.json', 'skills', 'plugins']) {
        const src = path.join(hostClaude, item);
        const dst = path.join(claudeDir, item);
        if (fs.existsSync(src)) {
          if (fs.statSync(src).isDirectory()) {
            fs.cpSync(src, dst, { recursive: true });
          } else if (item === 'settings.json') {
            try {
              const settings = JSON.parse(fs.readFileSync(src, 'utf8')) as { permissions?: { deny?: string[] } };
              if (settings.permissions?.deny) {
                settings.permissions.deny = settings.permissions.deny.filter((rule: string) => !rule.includes(':*|'));
              }
              fs.writeFileSync(dst, JSON.stringify(settings, null, 2));
            } catch {
              fs.copyFileSync(src, dst);
            }
          } else {
            fs.copyFileSync(src, dst);
          }
        }
      }
    }

    // 2. Combine user-level global skills (~/.claude/skills precedence over ~/.agents/skills)
    const hostAgentsSkills = path.join(USER_HOME, '.agents', 'skills');
    const stagedClaudeSkills = path.join(claudeDir, 'skills');
    if (fs.existsSync(hostAgentsSkills) && fs.statSync(hostAgentsSkills).isDirectory()) {
      fs.mkdirSync(stagedClaudeSkills, { recursive: true });
      for (const entry of fs.readdirSync(hostAgentsSkills)) {
        const targetSkill = path.join(stagedClaudeSkills, entry);
        if (!fs.existsSync(targetSkill)) {
          const sourceSkill = path.join(hostAgentsSkills, entry);
          fs.cpSync(sourceSkill, targetSkill, { recursive: true });
        }
      }
    }

    // 3. Pre-trust workspace in .claude.json
    const hostClaudeJson = path.join(USER_HOME, '.claude.json');
    let config: Record<string, unknown> = {};
    if (fs.existsSync(hostClaudeJson)) {
      try {
        config = JSON.parse(fs.readFileSync(hostClaudeJson, 'utf-8'));
      } catch {}
    }

    const projects = (config.projects || (config.projects = {})) as Record<string, { hasTrustDialogAccepted?: boolean }>;
    for (const p of ['/sandbox', `/sandbox/${projectName}`, projectRoot]) {
      projects[p] = { ...(projects[p] || {}), hasTrustDialogAccepted: true };
    }
    config.hasCompletedOnboarding = true;

    fs.writeFileSync(path.join(stageDir, '.claude.json'), JSON.stringify(config, null, 2));

    // 4. Safe git directory configuration
    fs.writeFileSync(path.join(stageDir, '.gitconfig'), '[safe]\n\tdirectory = *\n');
  }

  public buildExecArgs(
    sandboxName: string,
    projectName: string,
    args: string[],
    _credentials: Record<string, string>
  ): string[] {
    const execArgs = [
      'sandbox', 'exec',
      '--name', sandboxName,
      '--workdir', `/sandbox/${projectName}`,
      '--tty',
    ];

    execArgs.push('--', 'claude', ...args);
    return execArgs;
  }

  public async syncBack(
    sandboxName: string,
    projectRoot: string,
    projectName: string,
    workspaceWritePaths?: string[] | null
  ): Promise<void> {
    const hostHistory = path.join(USER_HOME, '.claude', 'history.jsonl');
    try {
      execFileSync('openshell', ['sandbox', 'download', sandboxName, '/sandbox/.claude/history.jsonl', hostHistory], {
        stdio: ['ignore', 'ignore', 'ignore'],
      });
    } catch {}

    syncWorkspaceBack(sandboxName, projectRoot, projectName, workspaceWritePaths);
  }
}
