#!/usr/bin/env node
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

type Auth = { tokens?: { access_token?: string; refresh_token?: string; account_id?: string } };
function openshell(args: string[], env = process.env): string {
  try { return execFileSync('openshell', args, { env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 30000 }); }
  catch { throw new Error(`OpenShell ${args.slice(0, 3).join(' ')} failed; inspect provider refresh status before retrying`); }
}
const providers = JSON.parse(openshell(['provider', 'list', '--output', 'json'])) as { providers: { name: string }[] };
const exists = providers.providers.some(provider => provider.name === 'codex-orca');
if (exists) {
  const status = openshell(['provider', 'refresh', 'status', 'codex-orca', '--credential-key', 'CODEX_AUTH_ACCESS_TOKEN']);
  if (/\bcodex-orca\s+CODEX_AUTH_ACCESS_TOKEN\s+oauth2_refresh_token\s+(refreshed|healthy)\b/.test(status)) {
    console.log('Codex Orca provider already has healthy gateway-owned OAuth refresh');
    process.exit(0);
  }
}
// CODEX_HOME lets Orca use an independent login without changing the user's
// normal Codex auth file or the existing OpenShell codex provider.
const file = path.join(process.env.CODEX_HOME || path.join(os.homedir(), '.codex'), 'auth.json');
const auth = JSON.parse(fs.readFileSync(file, 'utf8')) as Auth;
const access = auth.tokens?.access_token;
const refresh = auth.tokens?.refresh_token;
const account = auth.tokens?.account_id;
if (!access || !refresh || !account) throw new Error('Host Codex OAuth login is incomplete; sign in with codex on the host first');
const env = { ...process.env, CODEX_AUTH_ACCESS_TOKEN: access, CODEX_AUTH_REFRESH_TOKEN: refresh, CODEX_AUTH_ACCOUNT_ID: account };
if (!exists) openshell(['provider', 'create', '--name', 'codex-orca', '--type', 'codex-orca', '--global-profile', '--credential', 'CODEX_AUTH_ACCESS_TOKEN', '--credential', 'CODEX_AUTH_ACCOUNT_ID'], env);
openshell(['provider', 'refresh', 'configure', 'codex-orca', '--credential-key', 'CODEX_AUTH_ACCESS_TOKEN', '--strategy', 'oauth2-refresh-token', '--material', 'client_id=app_EMoamEEZ73f0CkXaXp7hrann', '--secret-material-env', 'refresh_token=CODEX_AUTH_REFRESH_TOKEN'], env);
openshell(['provider', 'refresh', 'rotate', 'codex-orca', '--credential-key', 'CODEX_AUTH_ACCESS_TOKEN'], env);
if (exists) openshell(['provider', 'update', 'codex-orca', '--credential', 'CODEX_AUTH_ACCOUNT_ID'], env);
console.log('Codex Orca provider is configured with gateway-owned OAuth refresh material');
