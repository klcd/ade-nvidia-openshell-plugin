import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import type { AgentAdapter, AgentType } from '../types.js';
import { USER_HOME } from '../config.js';
import { syncWorkspaceBack } from '../sandbox.js';

export class AntigravityAdapter implements AgentAdapter {
  public readonly type: AgentType = 'agy';
  public readonly binaryName = 'agy';
  public readonly containerImage = 'openshell-antigravity:latest';
  public readonly providerName = 'antigravity';

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
    const gemini = path.join(USER_HOME, '.gemini');
    const candidates = [
      path.join(gemini, 'antigravity-cli', 'antigravity-oauth-token'),
      path.join(gemini, 'oauth_creds.json'),
      path.join(gemini, 'google_accounts.json'),
    ];
    const result: Record<string, string> = {};
    for (const key of ['GOOGLE_OAUTH_ACCESS_TOKEN', 'GOOGLE_OAUTH_REFRESH_TOKEN', 'GOOGLE_OAUTH_ID_TOKEN']) {
      if (process.env[key]) result[key] = process.env[key]!;
    }
    const collectTokens = (value: unknown): void => {
      if (!value || typeof value !== 'object') return;
      for (const [key, item] of Object.entries(value)) {
        const normalized = key.toLowerCase();
        if (typeof item === 'string' && item) {
          if (normalized === 'access_token' || normalized === 'accesstoken' || normalized === 'token') {
            result.GOOGLE_OAUTH_ACCESS_TOKEN = item;
          } else if (normalized === 'refresh_token' || normalized === 'refreshtoken') {
            result.GOOGLE_OAUTH_REFRESH_TOKEN = item;
          } else if (normalized === 'id_token' || normalized === 'idtoken') {
            result.GOOGLE_OAUTH_ID_TOKEN = item;
          }
        } else {
          collectTokens(item);
        }
      }
    };
    for (const file of candidates) {
      try {
        const raw = fs.readFileSync(file, 'utf8').trim();
        if (!raw) continue;
        if (file.endsWith('.json')) {
          const parsed = JSON.parse(raw) as Record<string, unknown>;
          collectTokens(parsed);
        } else {
          try {
            const parsed = JSON.parse(raw) as Record<string, unknown>;
            collectTokens(parsed);
          } catch {
            result.GOOGLE_OAUTH_ACCESS_TOKEN = raw;
          }
        }
      } catch {
        // Try the next host credential location.
      }
    }
    return result;
  }

  public async stageConfiguration(stageDir: string, projectRoot: string, projectName: string): Promise<void> {
    const geminiDir = path.join(stageDir, '.gemini');
    const cliDir = path.join(geminiDir, 'antigravity-cli');
    const cacheDir = path.join(cliDir, 'cache');
    fs.mkdirSync(cacheDir, { recursive: true });

    // 1. Copy base ~/.gemini configuration
    const hostGemini = path.join(USER_HOME, '.gemini');
    if (fs.existsSync(hostGemini)) {
      for (const fname of ['oauth_creds.json', 'settings.json', 'google_accounts.json', 'installation_id', 'projects.json']) {
        const src = path.join(hostGemini, fname);
        if (fs.existsSync(src)) {
          fs.copyFileSync(src, path.join(geminiDir, fname));
        }
      }
    }

    // 2. Copy CLI state
    const hostCli = path.join(hostGemini, 'antigravity-cli');
    if (fs.existsSync(hostCli)) {
      for (const fname of ['antigravity-oauth-token', 'installation_id', 'jetbox_summaries_proto.pb']) {
        const src = path.join(hostCli, fname);
        if (fs.existsSync(src)) {
          fs.copyFileSync(src, path.join(cliDir, fname));
        }
      }
    }

    // 3. Stage jetski_state.pbtxt with complete onboarding
    const jetskiSrc = path.join(hostCli, 'jetski_state.pbtxt');
    let jetskiContent = '';
    if (fs.existsSync(jetskiSrc)) {
      try {
        jetskiContent = fs.readFileSync(jetskiSrc, 'utf-8');
      } catch {}
    }
    if (!jetskiContent.includes('agent_onboarding_completed')) {
      jetskiContent += '\nagent_onboarding_completed: AGENT_ONBOARDING_STATE_COMPLETED\n';
    }
    if (!jetskiContent.includes('POST_ONBOARDING_STEP_TYPE_MANAGER_WELCOME')) {
      jetskiContent += `
post_onboarding: {
  completed_steps: POST_ONBOARDING_STEP_TYPE_MANAGER_WELCOME
  completed_steps: POST_ONBOARDING_STEP_TYPE_USAGE_MODE
  completed_steps: POST_ONBOARDING_STEP_TYPE_AGENT_CONFIGURATION
  completed_steps: POST_ONBOARDING_STEP_TYPE_ADD_WORKSPACE
}
`;
    }
    fs.writeFileSync(path.join(cliDir, 'jetski_state.pbtxt'), jetskiContent.trim() + '\n');

    // 4. Stage cache/onboarding.json (bypasses theme and data collection prompt)
    const onboardingData = {
      consumerOnboardingComplete: true,
      enterpriseOnboardingComplete: false,
      onboardingComplete: true,
    };
    fs.writeFileSync(path.join(cacheDir, 'onboarding.json'), JSON.stringify(onboardingData, null, 2));

    // 5. Preconfigure settings.json (colorScheme, telemetryEnabled: false, trustedWorkspaces)
    let cliSettings: Record<string, unknown> = {};
    const hostSettings = path.join(hostCli, 'settings.json');
    if (fs.existsSync(hostSettings)) {
      try {
        cliSettings = JSON.parse(fs.readFileSync(hostSettings, 'utf-8'));
      } catch {}
    }
    cliSettings.colorScheme = cliSettings.colorScheme || 'tokyo night';
    cliSettings.telemetryEnabled = false;
    const tw = (cliSettings.trustedWorkspaces || (cliSettings.trustedWorkspaces = [])) as string[];
    for (const p of ['/sandbox', `/sandbox/${projectName}`, projectRoot]) {
      if (!tw.includes(p)) {
        tw.push(p);
      }
    }
    fs.writeFileSync(path.join(cliDir, 'settings.json'), JSON.stringify(cliSettings, null, 2));

    // 6. Safe git config
    fs.writeFileSync(path.join(stageDir, '.gitconfig'), '[safe]\n\tdirectory = *\n');
  }

  public buildExecArgs(
    sandboxName: string,
    projectName: string,
    args: string[],
    _credentials: Record<string, string>
  ): string[] {
    return [
      'sandbox', 'exec',
      '--name', sandboxName,
      '--workdir', `/sandbox/${projectName}`,
      '--tty',
      '--',
      'agy',
      ...args,
    ];
  }

  public async syncBack(
    sandboxName: string,
    projectRoot: string,
    projectName: string,
    workspaceWritePaths?: string[] | null
  ): Promise<void> {
    const cliDir = path.join(USER_HOME, '.gemini', 'antigravity-cli');
    for (const file of ['settings.json']) {
      try {
        execFileSync(
          'openshell',
          ['sandbox', 'download', sandboxName, `/sandbox/.gemini/antigravity-cli/${file}`, path.join(cliDir, file)],
          { stdio: ['ignore', 'ignore', 'ignore'] }
        );
      } catch {}
    }
    syncWorkspaceBack(sandboxName, projectRoot, projectName, workspaceWritePaths);
  }
}
