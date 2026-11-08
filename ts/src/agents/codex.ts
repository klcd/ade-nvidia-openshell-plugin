import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import type { AgentAdapter, AgentType } from '../types.js';
import { USER_HOME } from '../config.js';
import { syncWorkspaceBack } from '../sandbox.js';

export class CodexAdapter implements AgentAdapter {
  public readonly type: AgentType = 'codex';
  public readonly binaryName = 'codex';
  public readonly containerImage = 'openshell-codex:latest';
  public readonly providerName = 'codex';

  private authHome(): string {
    if (process.env.OPENSHELL_BRIDGE_REQUIRED === '1') {
      const dedicated = path.join(USER_HOME, '.local', 'share', 'orca-codex-auth');
      if (fs.existsSync(path.join(dedicated, 'auth.json'))) return dedicated;
    }
    return path.join(USER_HOME, '.codex');
  }

  public shouldBypassSandbox(args: string[], cwd: string): boolean {
    if (process.env.OPENSHELL_BRIDGE_REQUIRED === '1' || process.env.ORCA_OPENSHELL_REQUIRED === '1') return false;
    if (args.some(arg => ['--version', '-V', '--help', '-h'].includes(arg))) {
      return true;
    }
    // Orca background model discovery probes
    const joined = args.join(' ');
    if (joined.includes('features.plugins=false') || joined.includes('read-only')) {
      return true;
    }
    if (cwd.includes('rate-limit-pty-cwd') || cwd.startsWith('/tmp') || cwd.startsWith('/private/tmp')) {
      return true;
    }
    return false;
  }

  public async getCredentials(): Promise<Record<string, string>> {
    const authPath = path.join(this.authHome(), 'auth.json');
    try {
      const auth = JSON.parse(fs.readFileSync(authPath, 'utf8')) as Record<string, unknown>;
      const credentialKeys: Record<string, string> = {
        access_token: 'CODEX_AUTH_ACCESS_TOKEN', refresh_token: 'CODEX_AUTH_REFRESH_TOKEN',
        accesstoken: 'CODEX_AUTH_ACCESS_TOKEN', refreshtoken: 'CODEX_AUTH_REFRESH_TOKEN',
        id_token: 'CODEX_AUTH_ID_TOKEN', idtoken: 'CODEX_AUTH_ID_TOKEN',
        account_id: 'CODEX_AUTH_ACCOUNT_ID', apikey: 'OPENAI_API_KEY', api_key: 'OPENAI_API_KEY',
      };
      const result: Record<string, string> = {};
      const collect = (value: unknown): void => {
        if (!value || typeof value !== 'object') return;
        for (const [key, item] of Object.entries(value)) {
          const envName = credentialKeys[key.toLowerCase()];
          if (envName && typeof item === 'string' && item) result[envName] = item;
          else collect(item);
        }
      };
      collect(auth);
      if (process.env.OPENAI_API_KEY) result.OPENAI_API_KEY = process.env.OPENAI_API_KEY;
      return result;
    } catch {
      return process.env.OPENAI_API_KEY ? { OPENAI_API_KEY: process.env.OPENAI_API_KEY } : {};
    }
  }

  public async stageConfiguration(stageDir: string, _projectRoot: string, _projectName: string): Promise<void> {
    const codexDir = path.join(stageDir, '.codex');
    fs.mkdirSync(codexDir, { recursive: true });

    // Stage auth.json, config.toml, version.json
    const hostCodex = this.authHome();
    if (fs.existsSync(hostCodex)) {
      for (const item of ['auth.json', 'config.toml', 'version.json']) {
        const src = path.join(hostCodex, item);
        const dst = path.join(codexDir, item);
        if (fs.existsSync(src)) {
          fs.copyFileSync(src, dst);
        }
      }
    }

    fs.writeFileSync(path.join(stageDir, '.gitconfig'), '[safe]\n\tdirectory = *\n');
  }

  /** Codex parses the ID token locally; only a synthetic JWT enters Orca sandboxes. */
  public static prepareOrcaAuth(stageDir: string, accountId: string): void {
    const file = path.join(stageDir, '.codex', 'auth.json');
    if (!fs.existsSync(file) || !accountId) throw new Error('Orca Codex requires a separate host login with an account ID');
    const auth = JSON.parse(fs.readFileSync(file, 'utf8')) as { tokens?: Record<string, string>; last_refresh?: string };
    if (!auth.tokens) throw new Error('Orca Codex auth is missing token metadata');
    const part = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString('base64url');
    // Codex uses this nonsecret workspace identifier locally during routing
    // discovery, before the network proxy can resolve credential placeholders.
    auth.tokens.account_id = accountId;
    auth.tokens.id_token = `${part({ alg: 'none', typ: 'JWT' })}.${part({ sub: 'openshell-placeholder', exp: Math.floor(Date.now() / 1000) + 86400, 'https://api.openai.com/auth': { chatgpt_account_id: accountId } })}.placeholder`;
    auth.last_refresh = new Date().toISOString();
    fs.writeFileSync(file, JSON.stringify(auth), { mode: 0o600 });
  }

  public buildExecArgs(
    sandboxName: string,
    projectName: string,
    args: string[],
    _credentials: Record<string, string>
  ): string[] {
    const argsPrefix = [
      'sandbox', 'exec',
      '--name', sandboxName,
      '--workdir', `/sandbox/${projectName}`,
    ];
    // App-server is newline-delimited JSON-RPC over stdio; a PTY echoes input
    // and can corrupt the protocol stream. Interactive CLI sessions still need
    // a TTY for terminal control sequences.
    if (!args.includes('app-server')) argsPrefix.push('--tty');
    return [...argsPrefix, '--', 'codex', ...args];
  }

  public async syncBack(
    sandboxName: string,
    projectRoot: string,
    projectName: string,
    workspaceWritePaths?: string[] | null
  ): Promise<void> {
    syncWorkspaceBack(sandboxName, projectRoot, projectName, workspaceWritePaths);
  }
}
