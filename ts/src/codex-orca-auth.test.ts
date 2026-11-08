import { test, expect } from 'bun:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { CodexAdapter } from './agents/codex.js';
import { redactCredentialFiles, assertNoCredentialLeak } from './credential-security.js';

test('Orca Codex stages no raw OAuth token and leaves a locally parseable synthetic ID token', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'codex-orca-auth-test-'));
  const file = path.join(dir, '.codex', 'auth.json');
  const credentials = {
    CODEX_AUTH_ACCESS_TOKEN: 'raw-access-secret',
    CODEX_AUTH_REFRESH_TOKEN: 'raw-refresh-secret',
    CODEX_AUTH_ID_TOKEN: 'raw-id-secret',
    CODEX_AUTH_ACCOUNT_ID: 'raw-account-secret',
  };
  try {
    fs.mkdirSync(path.dirname(file));
    fs.writeFileSync(file, JSON.stringify({ auth_mode: 'chatgpt', tokens: {
      access_token: credentials.CODEX_AUTH_ACCESS_TOKEN,
      refresh_token: credentials.CODEX_AUTH_REFRESH_TOKEN,
      id_token: credentials.CODEX_AUTH_ID_TOKEN,
      account_id: credentials.CODEX_AUTH_ACCOUNT_ID,
    }, last_refresh: '2020-01-01T00:00:00Z' }));
    redactCredentialFiles(dir, credentials);
    CodexAdapter.prepareOrcaAuth(dir, credentials.CODEX_AUTH_ACCOUNT_ID);
    assertNoCredentialLeak(dir, Object.fromEntries(Object.entries(credentials).filter(([key]) => key !== 'CODEX_AUTH_ACCOUNT_ID')));
    const staged = JSON.parse(fs.readFileSync(file, 'utf8'));
    expect(staged.tokens.access_token).toBe('openshell:resolve:env:CODEX_AUTH_ACCESS_TOKEN');
    expect(staged.tokens.refresh_token).toBe('openshell:resolve:env:CODEX_AUTH_REFRESH_TOKEN');
    expect(staged.tokens.account_id).toBe(credentials.CODEX_AUTH_ACCOUNT_ID);
    expect(staged.tokens.id_token.split('.')).toHaveLength(3);
    const claims = JSON.parse(Buffer.from(staged.tokens.id_token.split('.')[1], 'base64url').toString());
    expect(claims.sub).toBe('openshell-placeholder');
    expect(claims['https://api.openai.com/auth'].chatgpt_account_id).toBe(credentials.CODEX_AUTH_ACCOUNT_ID);
    expect(staged.last_refresh).not.toBe('2020-01-01T00:00:00Z');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
