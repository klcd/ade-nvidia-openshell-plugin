import { execFileSync } from 'node:child_process';
import process from 'node:process';

/**
 * Reads a generic password from macOS Keychain.
 */
export function readKeychainPassword(serviceName: string): string | null {
  if (process.platform !== 'darwin') {
    return null;
  }
  try {
    const stdout = execFileSync(
      'security',
      ['find-generic-password', '-s', serviceName, '-w'],
      { encoding: 'utf-8', stdio: ['ignore', 'pipe', 'ignore'] }
    );
    return stdout.trim() || null;
  } catch {
    return null;
  }
}

/**
 * Extracts Claude Code OAuth access token from environment or macOS Keychain.
 */
export function getClaudeOAuthToken(): string | null {
  for (const envVar of ['CLAUDE_CODE_OAUTH_TOKEN', 'ANTHROPIC_API_KEY', 'CLAUDE_API_KEY']) {
    const val = process.env[envVar];
    if (val) {
      return val;
    }
  }

  const serviceCandidates = ['Claude Code-credentials'];
  try {
    const dump = execFileSync('security', ['dump-keychain'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
    const matches = dump.matchAll(/"svce"<blob>="?(Claude Code-credentials[^"\r\n]*)"?/g);
    for (const m of matches) {
      if (!serviceCandidates.includes(m[1])) {
        serviceCandidates.push(m[1]);
      }
    }
  } catch {}

  for (const svc of serviceCandidates) {
    const rawJson = readKeychainPassword(svc);
    if (rawJson) {
      try {
        const parsed = JSON.parse(rawJson);
        const token = parsed?.claudeAiOauth?.accessToken;
        if (typeof token === 'string' && token) {
          return token;
        }
      } catch {
        // Ignore JSON parse error
      }
    }
  }

  return null;
}
