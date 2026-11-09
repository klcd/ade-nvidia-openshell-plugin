import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import {
  DEFAULT_L7_WILDCARD_BINARIES,
  persistL7PolicyToJsonFile,
} from '../../../orca-plugin/src/policy/l7-mutator.ts';
import {
  recordSessionEgressRule,
  removeSessionEgressRule,
} from '../../../orca-plugin/src/state/session-egress.ts';
import { normalizeAgentId } from '../../../orca-plugin/src/types.ts';
import { detectProjectRoot, USER_HOME } from '../config.js';
import { ensureValidHostTmpDir } from '../sandbox.js';
import { resolveAgyProjectRoot } from './state.js';

export interface BlockedEgressInfo {
  host: string;
  port: number;
  method: string;
  path: string;
  binary: string;
  commandLine?: string;
}

export function detectBlockedEgress(
  commandLine: string,
  exitCode: number,
  stdoutText: string,
  stderrText: string
): BlockedEgressInfo | null {
  const combined = `${stdoutText}\n${stderrText}`;

  // 1. Check structured OpenShell L7 HTTP 403 policy denial payload
  if (combined.includes('X-OpenShell-Policy:') || combined.includes('"error":"policy_denied"')) {
    const jsonMatch = /\{"binary":[^\n]*?"rule_missing":\{[^\n]*?\}\}/.exec(combined);
    if (jsonMatch) {
      try {
        const parsed = JSON.parse(jsonMatch[0]) as {
          binary?: string;
          host?: string;
          method?: string;
          path?: string;
          port?: number;
          rule_missing?: {
            binary?: string;
            host?: string;
            method?: string;
            path?: string;
            port?: number;
          };
        };
        const rm = parsed.rule_missing || parsed;
        if (rm.host) {
          return {
            host: rm.host,
            port: Number(rm.port || 443),
            method: (rm.method || 'GET').toUpperCase(),
            path: rm.path || '/**',
            binary: rm.binary || '*',
            commandLine: commandLine.trim(),
          };
        }
      } catch {}
    }
  }

  // 2. Check non-zero exit code (or curl connection refusal) for commands targeting a URL
  const isNetworkFailure =
    exitCode !== 0 ||
    /Failed to connect|Couldn't connect to server|Connection refused|Could not resolve host|X-OpenShell-Policy:/i.test(
      combined
    );
  if (!isNetworkFailure) return null;

  const urlMatch = /(https?):\/\/([a-zA-Z0-9.-]+)(?::(\d+))?(\/[^\s"']*)?/.exec(commandLine);
  if (!urlMatch) return null;

  if (!/\b(curl|wget|fetch|http|gh|npm|bun|pip|poetry|cargo|go|python3?|node)\b/.test(commandLine)) {
    return null;
  }

  const scheme = urlMatch[1].toLowerCase();
  const host = urlMatch[2];
  const port = Number(urlMatch[3] || (scheme === 'http' ? 80 : 443));
  const rawPath = urlMatch[4] || '/**';
  const cleanPath = rawPath.split('?')[0] || '/**';
  const methodMatch = /(?:-X|--request)\s+['"]?(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)['"]?/i.exec(
    commandLine
  );
  const method = methodMatch
    ? methodMatch[1].toUpperCase()
    : /\s(?:-d|--data|--data-raw|--data-binary)\s/.test(commandLine)
      ? 'POST'
      : 'GET';

  return {
    host,
    port,
    method,
    path: cleanPath,
    binary: '*',
    commandLine: commandLine.trim(),
  };
}

export function promptUserForL7Approval(
  info: BlockedEgressInfo,
  sandboxName: string
): 'session' | 'workspace' | 'global' | 'deny' {
  if (process.env.ORCA_OPENSHELL_AUTO_APPROVE_SCOPE) {
    const s = process.env.ORCA_OPENSHELL_AUTO_APPROVE_SCOPE;
    if (s === 'session' || s === 'workspace' || s === 'global' || s === 'deny') return s;
  }
  if (process.platform !== 'darwin' || process.env.ORCA_OPENSHELL_DISABLE_POPUP === '1') {
    return 'deny';
  }

  const optSession = '1. Allow temporarily (This session - tagged Temporary)';
  const optWorkspace = '2. Allow (Add to project rules: .agents/policies/l7-custom.json)';
  const optGlobal = '3. Allow globally (All projects)';
  const optDeny = '4. Keep blocked (Deny)';

  const promptText =
    `OpenShell blocked outbound network egress in sandbox ${sandboxName}:\\n\\n` +
    `  ${info.method} https://${info.host}:${info.port}${info.path}\\n\\n` +
    `Select how to handle this L7 rule:`;

  const script = [
    `set opts to {${JSON.stringify(optSession)}, ${JSON.stringify(optWorkspace)}, ${JSON.stringify(optGlobal)}, ${JSON.stringify(optDeny)}}`,
    `set choice to choose from list opts with title "OpenShell L7 Network Policy" with prompt "${promptText}" default items {${JSON.stringify(optSession)}} OK button name "Apply Rule" cancel button name "Keep Blocked"`,
    `if choice is false then return "deny"`,
    `return item 1 of choice`,
  ].join('\n');

  try {
    const out = execFileSync('osascript', ['-e', script], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 60000,
    }).trim();
    if (out.startsWith('1.')) return 'session';
    if (out.startsWith('2.')) return 'workspace';
    if (out.startsWith('3.')) return 'global';
    return 'deny';
  } catch {
    return 'deny';
  }
}

export async function drainL7RequestQueue(projectRoot: string, sandboxName: string): Promise<void> {
  const reqDir = path.join(projectRoot, '.orca-openshell-l7-requests');
  if (!fs.existsSync(reqDir)) return;
  try {
    const files = fs.readdirSync(reqDir).filter(f => f.endsWith('.json')).sort();
    for (const file of files) {
      const fullPath = path.join(reqDir, file);
      try {
        const req = JSON.parse(fs.readFileSync(fullPath, 'utf8')) as {
          scope?: 'session' | 'workspace' | 'global';
          host?: string;
          port?: number;
          method?: string;
          path?: string;
          binary?: string;
        };
        fs.unlinkSync(fullPath);
        if (req.host) {
          await runAgyPolicyAdd([
            '--scope', req.scope || 'session',
            '--host', req.host,
            '--port', String(req.port || 443),
            '--method', req.method || 'GET',
            '--path', req.path || '/**',
            '--binary', req.binary || '*',
            '--sandbox', sandboxName,
            '--project-root', projectRoot,
          ]);
        }
      } catch {
        try {
          fs.unlinkSync(fullPath);
        } catch {}
      }
    }
    if (fs.readdirSync(reqDir).length === 0) {
      try {
        fs.rmdirSync(reqDir);
      } catch {}
    }
  } catch {}
}

export async function runAgyPolicyAdd(rawArgs: string[]): Promise<number> {
  process.env.AG_SANDBOX_HOST_INTERNAL = '1';
  delete process.env.ANTIGRAVITY_HARNESS_PATH;
  ensureValidHostTmpDir();

  let scope: 'session' | 'workspace' | 'global' = 'session';
  let host = '';
  let port = 443;
  let method = 'GET';
  let urlPath = '/**';
  let binary = '*';
  let sandboxName = '';
  let agent = 'antigravity';
  let triggerCommand = '';
  let explicitProjectRoot = '';

  for (let i = 0; i < rawArgs.length; i++) {
    const arg = rawArgs[i];
    if (arg === '--scope' && rawArgs[i + 1]) scope = rawArgs[++i] as any;
    else if (arg === '--host' && rawArgs[i + 1]) host = rawArgs[++i];
    else if (arg === '--port' && rawArgs[i + 1]) port = Number(rawArgs[++i]) || 443;
    else if (arg === '--method' && rawArgs[i + 1]) method = rawArgs[++i].toUpperCase();
    else if (arg === '--path' && rawArgs[i + 1]) urlPath = rawArgs[++i];
    else if (arg === '--binary' && rawArgs[i + 1]) binary = rawArgs[++i];
    else if (arg === '--sandbox' && rawArgs[i + 1]) sandboxName = rawArgs[++i];
    else if (arg === '--agent' && rawArgs[i + 1]) agent = rawArgs[++i];
    else if (arg === '--trigger-command' && rawArgs[i + 1]) triggerCommand = rawArgs[++i];
    else if (arg === '--project-root' && rawArgs[i + 1]) explicitProjectRoot = rawArgs[++i];
  }

  if (!host) {
    console.error(
      'Usage: agent-box policy-add --scope <session|workspace|global> --host <domain> [--port 443] [--method GET] [--path "/**"]'
    );
    return 1;
  }

  const normalizedPath = urlPath.startsWith('/') ? urlPath : `/${urlPath}`;
  const ruleName = `${host.replace(/[^a-zA-Z0-9]+/g, '_')}_l7`;
  const effectiveBinaries = binary === '*' ? DEFAULT_L7_WILDCARD_BINARIES : [binary];
  const projectRoot =
    explicitProjectRoot && fs.existsSync(explicitProjectRoot)
      ? detectProjectRoot(explicitProjectRoot)
      : resolveAgyProjectRoot(process.cwd(), Number(process.env.AG_HARNESS_PID || process.ppid));
  const resolvedAgent = normalizeAgentId(agent) || 'antigravity';

  if (scope === 'workspace' || scope === 'global') {
    const orcaPolicyDir =
      process.env.ORCA_OPENSHELL_POLICY_DIR ||
      path.join(USER_HOME, '.agents', 'orca-openshell-policies');
    const targetFile =
      scope === 'workspace'
        ? path.join(projectRoot, '.agents', 'policies', 'l7-custom.json')
        : path.join(orcaPolicyDir, `${resolvedAgent}.json`);

    persistL7PolicyToJsonFile({
      targetFile,
      ruleName,
      host,
      port,
      action: 'allow',
      method,
      urlPath: normalizedPath,
      effectiveBinaries,
      triggerCommand,
    });
    console.log(`Saved persistent L7 rule (${scope}) to ${targetFile}`);

    // Remove any matching temporary rule now that it is saved permanently
    removeSessionEgressRule({ workspacePath: projectRoot, host, port }, USER_HOME);
  }

  const targetSandboxes: string[] = [];
  if (sandboxName) {
    targetSandboxes.push(sandboxName);
  } else {
    try {
      const out = execFileSync('openshell', ['sandbox', 'list'], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
      });
      for (const line of out.split(/\r?\n/)) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('NAME') || trimmed.startsWith('No sandboxes')) continue;
        const parts = trimmed.split(/\s+/);
        const name = parts[0];
        const phase = parts[parts.length - 1] || '';
        if (name && phase.toLowerCase() === 'ready') {
          targetSandboxes.push(name);
        }
      }
    } catch {}
  }

  const binFlags = effectiveBinaries.flatMap(b => ['--binary', b]);
  const accessPreset = ['GET', 'HEAD', 'OPTIONS'].includes(method) ? 'read-only' : 'read-write';
  const isWildcardPath = normalizedPath === '/**' || normalizedPath === '**';

  for (const sb of targetSandboxes) {
    try {
      execFileSync(
        'openshell',
        [
          'policy', 'update', sb,
          ...(isWildcardPath && method !== 'DELETE' ? ['--wait'] : []),
          '--rule-name', ruleName,
          ...binFlags,
          '--add-endpoint', `${host}:${port}:${accessPreset}:rest:enforce`,
        ],
        { stdio: ['ignore', 'pipe', 'pipe'], timeout: 25000 }
      );
      if (!isWildcardPath || method === 'DELETE') {
        execFileSync(
          'openshell',
          [
            'policy', 'update', sb,
            '--wait',
            '--rule-name', ruleName,
            ...binFlags,
            '--add-allow', `${host}:${port}:${method}:${normalizedPath}`,
          ],
          { stdio: ['ignore', 'pipe', 'pipe'], timeout: 25000 }
        );
      }
      console.log(`Live-applied L7 rule (${method} https://${host}:${port}${normalizedPath}) to sandbox ${sb}`);
    } catch (err) {
      console.error(`Failed to update sandbox ${sb}: ${err}`);
      return 1;
    }
  }

  if (scope === 'session') {
    try {
      recordSessionEgressRule(
        {
          sandboxName: targetSandboxes[0] || sandboxName || undefined,
          workspacePath: projectRoot,
          agent: resolvedAgent,
          ruleName,
          host,
          port,
          action: 'allow',
          method,
          path: normalizedPath,
          binary,
          ...(triggerCommand?.trim() ? { triggerCommand: triggerCommand.trim() } : {}),
          createdAt: new Date().toISOString(),
        },
        USER_HOME
      );
    } catch {}
  }

  return 0;
}
