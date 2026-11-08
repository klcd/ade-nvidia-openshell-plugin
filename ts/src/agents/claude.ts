import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import type { AgentAdapter, AgentType } from '../types.js';
import { USER_HOME, detectProjectRoot } from '../config.js';
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

const HOST_DIR_FLAGS = new Set(['--add-dir', '--plugin-dir', '--plugin-dir-no-mcp']);

export class ClaudeAdapter implements AgentAdapter {
  public readonly type: AgentType = 'claude';
  public readonly binaryName = 'claude';
  public readonly containerImage = 'openshell-claude:latest';
  public readonly providerName = 'claude-code';

  public static isStreamJsonMode(args: string[]): boolean {
    for (let i = 0; i < args.length; i++) {
      const arg = args[i];
      if (arg === '--output-format=stream-json' || arg === '--input-format=stream-json') return true;
      if ((arg === '--output-format' || arg === '--input-format') && args[i + 1] === 'stream-json') return true;
    }
    return false;
  }

  public static projectSlug(dirPath: string): string {
    return dirPath.replace(/[^a-zA-Z0-9-]/g, '-');
  }

  private static mapHostDirArg(
    hostPath: string,
    projectRoot: string,
    projectName: string
  ): { containerPath: string; slug: string | null } {
    if (hostPath.startsWith('/sandbox/') || hostPath === '/sandbox') {
      return { containerPath: hostPath, slug: null };
    }
    const resolved = path.resolve(hostPath);
    if (resolved === projectRoot) {
      return { containerPath: `/sandbox/${projectName}`, slug: null };
    }
    if (resolved.startsWith(projectRoot + path.sep)) {
      const rel = resolved.slice(projectRoot.length + 1).split(path.sep).join('/');
      return { containerPath: `/sandbox/${projectName}/${rel}`, slug: null };
    }
    const slug = crypto.createHash('sha256').update(resolved).digest('hex').slice(0, 12);
    return { containerPath: `/sandbox/.claude/orca-host-dirs/${slug}`, slug };
  }

  public shouldBypassSandbox(args: string[], cwd: string): boolean {
    if (
      process.env.OPENSHELL_BRIDGE_REQUIRED === '1' ||
      process.env.ORCA_OPENSHELL_REQUIRED === '1' ||
      process.env.ORCA_STRUCTURED_SESSION === '1'
    ) {
      return false;
    }
    if (args.some(arg => ['--version', '-V', '--help', '-h'].includes(arg))) {
      return true;
    }
    // Orca background model/command discovery probes (-p ... --settings '{"disableAllHooks":true}')
    const joined = args.join(' ');
    if (joined.includes('"disableAllHooks":true') || joined.includes('dontAsk')) {
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

    // 3. Stage existing project transcripts so --resume works inside the sandbox
    const hostSlug = ClaudeAdapter.projectSlug(projectRoot);
    const containerSlug = ClaudeAdapter.projectSlug(`/sandbox/${projectName}`);
    const containerRoot = `/sandbox/${projectName}`;
    const candidateConfigDirs = [...new Set([
      hostClaude,
      ...(process.env.CLAUDE_CONFIG_DIR ? [process.env.CLAUDE_CONFIG_DIR] : []),
    ])];
    for (const cfgDir of candidateConfigDirs) {
      const hostProjTranscripts = path.join(cfgDir, 'projects', hostSlug);
      if (fs.existsSync(hostProjTranscripts) && fs.statSync(hostProjTranscripts).isDirectory()) {
        const dstProjTranscripts = path.join(claudeDir, 'projects', containerSlug);
        fs.mkdirSync(dstProjTranscripts, { recursive: true });
        for (const entry of fs.readdirSync(hostProjTranscripts)) {
          if (!entry.endsWith('.jsonl')) continue;
          const srcFile = path.join(hostProjTranscripts, entry);
          const dstFile = path.join(dstProjTranscripts, entry);
          try {
            const content = fs.readFileSync(srcFile, 'utf8').replaceAll(projectRoot, containerRoot);
            fs.writeFileSync(dstFile, content);
          } catch {}
        }
      }
    }

    // 4. Stage any host directories referenced by --add-dir / --plugin-dir / --plugin-dir-no-mcp
    const rawArgs = process.argv.slice(2);
    for (let i = 0; i < rawArgs.length; i++) {
      const arg = rawArgs[i];
      let hostDir: string | null = null;
      if (HOST_DIR_FLAGS.has(arg) && i + 1 < rawArgs.length) {
        hostDir = rawArgs[++i];
      } else {
        for (const flag of HOST_DIR_FLAGS) {
          if (arg.startsWith(`${flag}=`)) {
            hostDir = arg.slice(flag.length + 1);
            break;
          }
        }
      }
      if (!hostDir) continue;
      const mapped = ClaudeAdapter.mapHostDirArg(hostDir, projectRoot, projectName);
      if (mapped.slug) {
        const stagedDir = path.join(claudeDir, 'orca-host-dirs', mapped.slug);
        fs.mkdirSync(stagedDir, { recursive: true });
        try {
          if (fs.existsSync(hostDir) && fs.statSync(hostDir).isDirectory()) {
            fs.cpSync(hostDir, stagedDir, { recursive: true });
          }
        } catch {}
      }
    }

    // 5. Pre-trust workspace in .claude.json
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

    // 6. Safe git directory configuration
    fs.writeFileSync(path.join(stageDir, '.gitconfig'), '[safe]\n\tdirectory = *\n');
  }

  public buildExecArgs(
    sandboxName: string,
    projectName: string,
    args: string[],
    _credentials: Record<string, string>
  ): string[] {
    const streamJson = ClaudeAdapter.isStreamJsonMode(args);
    const execArgs = [
      'sandbox', 'exec',
      '--name', sandboxName,
      '--workdir', `/sandbox/${projectName}`,
      streamJson ? '--no-tty' : '--tty',
    ];

    if (streamJson) {
      const passthroughEnvKeys = [
        'CLAUDE_CODE_ENTRYPOINT',
        'CLAUDE_AGENT_SDK_VERSION',
        'CLAUDE_CODE_SDK_READS_SESSION_STATE',
        'CLAUDE_CODE_EMIT_SESSION_STATE_EVENTS',
        'CLAUDE_CODE_ARTIFACT',
        'CLAUDE_CODE_ENABLE_SDK_FILE_CHECKPOINTING',
        'ORCA_STRUCTURED_SESSION',
        'ORCA_AGENT_SESSION_ID',
      ];
      for (const key of passthroughEnvKeys) {
        if (process.env[key]) {
          execArgs.push('--env', `${key}=${process.env[key]}`);
        }
      }
    }

    const projectRoot = detectProjectRoot(process.cwd());
    const rewrittenArgs: string[] = [];
    for (let i = 0; i < args.length; i++) {
      const arg = args[i];
      if (HOST_DIR_FLAGS.has(arg) && i + 1 < args.length) {
        const mapped = ClaudeAdapter.mapHostDirArg(args[++i], projectRoot, projectName);
        rewrittenArgs.push(arg, mapped.containerPath);
        continue;
      }
      let matchedEquals = false;
      for (const flag of HOST_DIR_FLAGS) {
        if (arg.startsWith(`${flag}=`)) {
          const val = arg.slice(flag.length + 1);
          const mapped = ClaudeAdapter.mapHostDirArg(val, projectRoot, projectName);
          rewrittenArgs.push(`${flag}=${mapped.containerPath}`);
          matchedEquals = true;
          break;
        }
      }
      if (!matchedEquals) {
        rewrittenArgs.push(arg);
      }
    }

    execArgs.push('--', 'claude', ...rewrittenArgs);
    return execArgs;
  }

  public async syncTranscriptsOnly(
    sandboxName: string,
    projectRoot: string,
    projectName: string
  ): Promise<void> {
    const hostHistory = path.join(USER_HOME, '.claude', 'history.jsonl');
    try {
      execFileSync('openshell', ['sandbox', 'download', sandboxName, '/sandbox/.claude/history.jsonl', hostHistory], {
        stdio: ['ignore', 'ignore', 'ignore'],
        timeout: 15000,
      });
    } catch {}

    const hostSlug = ClaudeAdapter.projectSlug(projectRoot);
    const containerSlug = ClaudeAdapter.projectSlug(`/sandbox/${projectName}`);
    const containerRoot = `/sandbox/${projectName}`;
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), `claude-transcripts-${sandboxName}-`));
    try {
      execFileSync(
        'openshell',
        ['sandbox', 'download', sandboxName, `/sandbox/.claude/projects/${containerSlug}`, tmpDir],
        { stdio: ['ignore', 'ignore', 'ignore'], timeout: 15000 }
      );
      const targetDirs = [...new Set([
        path.join(USER_HOME, '.claude', 'projects', hostSlug),
        ...(process.env.CLAUDE_CONFIG_DIR ? [path.join(process.env.CLAUDE_CONFIG_DIR, 'projects', hostSlug)] : []),
      ])];
      for (const entry of fs.readdirSync(tmpDir)) {
        if (!entry.endsWith('.jsonl')) continue;
        const srcFile = path.join(tmpDir, entry);
        if (!fs.statSync(srcFile).isFile()) continue;
        const content = fs.readFileSync(srcFile, 'utf8').replaceAll(containerRoot, projectRoot);
        for (const dstDir of targetDirs) {
          fs.mkdirSync(dstDir, { recursive: true });
          fs.writeFileSync(path.join(dstDir, entry), content);
        }
      }
    } catch {} finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }

  public async syncBack(
    sandboxName: string,
    projectRoot: string,
    projectName: string,
    workspaceWritePaths?: string[] | null
  ): Promise<void> {
    await this.syncTranscriptsOnly(sandboxName, projectRoot, projectName);
    syncWorkspaceBack(sandboxName, projectRoot, projectName, workspaceWritePaths);
  }
}
