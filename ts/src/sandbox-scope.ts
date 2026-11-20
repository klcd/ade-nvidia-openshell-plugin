import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import type { NetworkEndpoint, NetworkPolicy, OpenShellPolicy } from './types.js';

const WORKSPACE_WRITE_ENV = 'ORCA_SANDBOX_WRITE_PATHS';

export interface WorkspaceFileScope {
  /** null = entire repository readable; string[] = only these relative paths staged/readable */
  readPaths: string[] | null;
  /** null = entire staged scope writable back to host; [] = read-only; string[] = only these relative paths writable */
  writePaths: string[] | null;
}

function assertSafeRelativePath(
  projectRoot: string,
  candidate: string,
  label: string,
  allowMissing: boolean
): string {
  if (!candidate || path.isAbsolute(candidate) || candidate.includes('\0')) {
    throw new Error(`Invalid ${label} path: ${candidate}`);
  }
  const rel = path.normalize(candidate);
  if (rel === '.' || rel === '..' || rel.startsWith(`..${path.sep}`)) {
    throw new Error(`${label} path must stay inside the project: ${candidate}`);
  }
  if (rel === '.git' || rel.startsWith(`.git${path.sep}`)) {
    throw new Error(`${label} cannot include .git metadata`);
  }

  const rootAbs = path.resolve(projectRoot);
  const absolute = path.resolve(rootAbs, rel);
  if (!absolute.startsWith(`${rootAbs}${path.sep}`)) {
    throw new Error(`${label} path escapes the project: ${candidate}`);
  }

  let cursor = rootAbs;
  const parts = rel.split(path.sep);
  for (let i = 0; i < parts.length; i++) {
    cursor = path.join(cursor, parts[i]!);
    if (!fs.existsSync(cursor)) {
      if (!allowMissing) {
        throw new Error(`${label} path does not exist: ${candidate}`);
      }
      break;
    }
    const stat = fs.lstatSync(cursor);
    if (stat.isSymbolicLink()) {
      throw new Error(`${label} cannot traverse symlinks: ${candidate}`);
    }
    if (i < parts.length - 1 && !stat.isDirectory()) {
      throw new Error(`${label} parent is not a directory: ${candidate}`);
    }
  }

  if (fs.existsSync(absolute)) {
    const stat = fs.statSync(absolute);
    if (!stat.isFile() && !stat.isDirectory()) {
      throw new Error(`${label} path must be a file or directory: ${candidate}`);
    }
  }
  return rel;
}

export function parseWorkspacePathList(raw: string, label: string): string[] | null {
  const trimmed = raw.trim();
  if (trimmed === '*') return null;
  if (trimmed.startsWith('[')) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      throw new Error(`${label} must be a JSON array of relative paths or comma-separated list`);
    }
    if (!Array.isArray(parsed) || !parsed.every(item => typeof item === 'string')) {
      throw new Error(`${label} must be a JSON array of relative paths`);
    }
    if (parsed.length === 1 && parsed[0] === '*') return null;
    if (parsed.length > 200) throw new Error(`${label} may contain at most 200 paths`);
    return parsed as string[];
  }
  if (!trimmed) return [];
  const items = trimmed.split(',').map(s => s.trim()).filter(Boolean);
  if (items.length === 1 && items[0] === '*') return null;
  if (items.length > 200) throw new Error(`${label} may contain at most 200 paths`);
  return items;
}

export function validateWorkspacePaths(
  projectRoot: string,
  candidates: string[],
  label = 'workspace path',
  options?: { allowMissing?: boolean }
): string[] {
  if (candidates.length > 200) throw new Error(`${label} may contain at most 200 paths`);
  const allowMissing = options?.allowMissing ?? false;
  const normalized = new Set<string>();
  for (const candidate of candidates) {
    normalized.add(assertSafeRelativePath(projectRoot, candidate, label, allowMissing));
  }
  const paths = [...normalized].sort();
  for (let i = 0; i < paths.length; i++) {
    if (paths.some((other, j) => i !== j && paths[i]!.startsWith(`${other}${path.sep}`))) {
      throw new Error(`${label} cannot contain both a path and its descendant`);
    }
  }
  return paths;
}

export function isRelativePathAllowed(relative: string, scopePaths: string[] | null): boolean {
  if (scopePaths === null) return true;
  const norm = path.normalize(relative);
  return scopePaths.some(scope => norm === scope || norm.startsWith(`${scope}${path.sep}`));
}

export function intersectWorkspacePaths(
  parentPaths: string[] | null,
  requestedPaths: string[] | null,
  label = 'file scope'
): string[] | null {
  if (parentPaths === null) return requestedPaths;
  if (requestedPaths === null) return [...parentPaths];
  for (const req of requestedPaths) {
    if (!isRelativePathAllowed(req, parentPaths)) {
      throw new Error(`${label} path "${req}" exceeds coordinator grant`);
    }
  }
  return [...requestedPaths];
}

export function resolveSubagentFileScope(
  projectRoot: string,
  readRaw: string | null,
  writeRaw: string | null,
  parentScope?: WorkspaceFileScope | null
): WorkspaceFileScope | null {
  const hasExplicit = readRaw !== null || writeRaw !== null;
  if (!hasExplicit) {
    return parentScope ? { readPaths: parentScope.readPaths ? [...parentScope.readPaths] : null, writePaths: parentScope.writePaths ? [...parentScope.writePaths] : null } : null;
  }

  const parsedRead = readRaw !== null ? parseWorkspacePathList(readRaw, '--read-paths') : null;
  const parsedWrite = writeRaw !== null ? parseWorkspacePathList(writeRaw, '--write-paths') : null;

  const validatedWrite =
    writeRaw !== null
      ? (parsedWrite === null ? null : validateWorkspacePaths(projectRoot, parsedWrite, '--write-paths', { allowMissing: true }))
      : [];

  let validatedRead: string[] | null;
  if (readRaw !== null) {
    validatedRead = parsedRead === null ? null : validateWorkspacePaths(projectRoot, parsedRead, '--read-paths', { allowMissing: false });
  } else {
    // Only --write-paths given: confine reads strictly to --write-paths
    validatedRead = validatedWrite === null ? null : [...validatedWrite];
  }

  // Ensure anything explicitly writable is also staged/readable unless readPaths is unrestricted
  if (validatedRead !== null && validatedWrite !== null && validatedWrite.length > 0) {
    const combined = new Set<string>(validatedRead);
    for (const w of validatedWrite) {
      if (!isRelativePathAllowed(w, validatedRead)) {
        combined.add(w);
      }
    }
    validatedRead = collapseWorkspacePaths([...combined]);
  }

  return {
    readPaths: intersectWorkspacePaths(parentScope?.readPaths ?? null, validatedRead, '--read-paths'),
    writePaths: intersectWorkspacePaths(parentScope?.writePaths ?? null, validatedWrite, '--write-paths'),
  };
}

function collapseWorkspacePaths(paths: string[]): string[] {
  const sorted = [...new Set(paths.map(p => path.normalize(p)))].sort();
  return sorted.filter(
    (p, idx) => !sorted.some((other, j) => idx !== j && p.startsWith(`${other}${path.sep}`))
  );
}

export function getStagedUploadPaths(scope: WorkspaceFileScope | null): string[] | null {
  if (!scope || scope.readPaths === null) return null;
  const combined = [...scope.readPaths, ...(scope.writePaths ?? [])];
  return collapseWorkspacePaths(combined);
}

export function stageScopedWorkspace(
  projectRoot: string,
  projectName: string,
  stageRoot: string,
  stagedPaths: string[]
): string {
  const targetRoot = path.join(stageRoot, projectName);
  fs.mkdirSync(targetRoot, { recursive: true });
  for (const rel of collapseWorkspacePaths(stagedPaths)) {
    const src = path.join(projectRoot, rel);
    const dst = path.join(targetRoot, rel);
    if (!fs.existsSync(src)) {
      // Missing write target inside an existing directory: prepare parent dir in sandbox
      fs.mkdirSync(path.dirname(dst), { recursive: true });
      continue;
    }
    const stat = fs.lstatSync(src);
    if (stat.isSymbolicLink()) continue;
    if (stat.isDirectory()) {
      fs.mkdirSync(dst, { recursive: true });
      fs.cpSync(src, dst, {
        recursive: true,
        filter: (entryPath) => {
          const base = path.basename(entryPath);
          if (base === '.git') return false;
          try {
            return !fs.lstatSync(entryPath).isSymbolicLink();
          } catch {
            return false;
          }
        },
      });
    } else if (stat.isFile()) {
      fs.mkdirSync(path.dirname(dst), { recursive: true });
      fs.copyFileSync(src, dst);
      fs.chmodSync(dst, stat.mode & 0o777);
    }
  }
  return targetRoot;
}

/**
 * Returns null for the legacy full-workspace mode. Paseo agents default to an
 * empty write allowlist so they cannot edit the shared workspace implicitly.
 */
export function getWorkspaceWritePaths(projectRoot: string): string[] | null {
  const encoded = process.env[WORKSPACE_WRITE_ENV];
  if (encoded === undefined) {
    return process.env.PASEO_AGENT_ID ? [] : null;
  }

  let value: unknown;
  try {
    value = JSON.parse(encoded);
  } catch {
    throw new Error(`${WORKSPACE_WRITE_ENV} must be a JSON array of relative paths`);
  }
  if (!Array.isArray(value) || !value.every(item => typeof item === 'string')) {
    throw new Error(`${WORKSPACE_WRITE_ENV} must be a JSON array of relative paths`);
  }
  return validateWorkspacePaths(projectRoot, value as string[], 'workspace write');
}

/** Restrict project writes while leaving the agent's private home config writable. */
export function applyWorkspaceWriteScope(
  policy: OpenShellPolicy,
  projectName: string,
  agentHomePath: '.claude' | '.codex' | '.gemini',
  writePaths: string[]
): void {
  const filesystem = policy.filesystem_policy ??= { read_only: [], read_write: [] };
  const sandboxRoot = '/sandbox';
  const workspaceRoot = path.posix.join(sandboxRoot, projectName);

  filesystem.include_workdir = false;
  filesystem.read_only = (filesystem.read_only ?? []).filter(p => p !== sandboxRoot && !p.startsWith(`${sandboxRoot}/`));
  filesystem.read_write = (filesystem.read_write ?? []).filter(p => p !== sandboxRoot && !p.startsWith(`${sandboxRoot}/`));
  filesystem.read_only.push(sandboxRoot);
  filesystem.read_write.push(path.posix.join(sandboxRoot, agentHomePath));
  if (agentHomePath === '.claude') filesystem.read_write.push('/sandbox/.claude.json');

  for (const rel of writePaths) {
    filesystem.read_write.push(path.posix.join(workspaceRoot, ...rel.split(path.sep)));
  }
  filesystem.read_only = [...new Set(filesystem.read_only)];
  filesystem.read_write = [...new Set(filesystem.read_write)];
  policy.landlock ??= { compatibility: 'hard_requirement' };
  policy.landlock.compatibility = 'hard_requirement';
}

export function getExtraProviderNames(): string[] {
  const encoded = process.env.ORCA_SANDBOX_EXTRA_PROVIDERS;
  if (!encoded) return [];
  let value: unknown;
  try {
    value = JSON.parse(encoded);
  } catch {
    throw new Error('ORCA_SANDBOX_EXTRA_PROVIDERS must be a JSON array of provider names');
  }
  if (!Array.isArray(value) || !value.every(item => typeof item === 'string' && /^[a-z0-9][a-z0-9-]*$/.test(item))) {
    throw new Error('ORCA_SANDBOX_EXTRA_PROVIDERS must contain valid provider names');
  }
  return [...new Set(value as string[])];
}

const RESERVED_PROVIDER_HOSTS = new Set([
  'api.anthropic.com',
  'statsig.anthropic.com',
  'statsigapi.net',
  'sentry.io',
  'http-intake.logs.us5.datadoghq.com',
  'api.openai.com',
  'auth.openai.com',
  'chatgpt.com',
  'ab.chatgpt.com',
  'daily-cloudcode-pa.googleapis.com',
  'cloudcode-pa.googleapis.com',
  'www.googleapis.com',
  'oauth2.googleapis.com',
  'accounts.google.com',
  'storage.googleapis.com',
]);

const SAFE_READ_ONLY_CONTAINER_PREFIXES = [
  '/bin',
  '/usr',
  '/lib',
  '/lib64',
  '/opt',
  '/etc/ssl',
  '/etc/ca-certificates',
  '/proc',
  '/dev/urandom',
  '/var/log',
];

const SAFE_READ_WRITE_CONTAINER_PREFIXES = ['/tmp', '/var/tmp'];

function resolveLocalBin(name: string): string {
  for (const dir of (process.env.PATH || '').split(path.delimiter)) {
    if (!dir) continue;
    const candidate = path.join(dir, name);
    try {
      fs.accessSync(candidate, fs.constants.X_OK);
      if (fs.statSync(candidate).isFile()) return candidate;
    } catch {}
  }
  return name;
}

function isDisallowedEgressHost(rawHost: string): string | null {
  const host = rawHost.trim().toLowerCase();
  if (!host) return 'Empty host';
  if (host.includes('://') || host.includes('/') || host.includes('*') || /\s/.test(host)) {
    return `Host must be a plain domain name without schemes, paths, or wildcards: ${rawHost}`;
  }
  if (!/^[a-z0-9.-]+$/.test(host) || !host.includes('.') || host.startsWith('.') || host.endsWith('.')) {
    return `Invalid hostname: ${rawHost}`;
  }
  if (
    host === 'localhost' ||
    host.endsWith('.localhost') ||
    host.endsWith('.local') ||
    host.endsWith('.internal')
  ) {
    return `Local/internal hostnames are forbidden: ${rawHost}`;
  }
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    const octets = host.split('.').map(Number);
    if (octets.some(o => o < 0 || o > 255)) return `Invalid IPv4 host: ${rawHost}`;
    const [a, b] = octets;
    if (
      a === 0 ||
      a === 10 ||
      a === 127 ||
      (a === 169 && b === 254) ||
      (a === 172 && b !== undefined && b >= 16 && b <= 31) ||
      (a === 192 && b === 168)
    ) {
      return `Loopback, metadata, and RFC1918 addresses are forbidden: ${rawHost}`;
    }
  }
  if (RESERVED_PROVIDER_HOSTS.has(host)) {
    return `Reserved provider host cannot be redefined in subagent policy: ${rawHost}`;
  }
  return null;
}

function validateSafeContainerFsPath(rawPath: string, kind: 'read_only' | 'read_write'): string {
  if (typeof rawPath !== 'string' || !rawPath.startsWith('/') || rawPath.includes('\0')) {
    throw new Error(`filesystem_policy.${kind} path must be an absolute container path: ${String(rawPath)}`);
  }
  const normalized = path.posix.normalize(rawPath);
  if (normalized === '/' || normalized.includes('..') || normalized === '/sandbox' || normalized.startsWith('/sandbox/')) {
    throw new Error(
      `filesystem_policy.${kind} cannot target / or /sandbox directly (use readPaths/writePaths for repo scoping): ${rawPath}`
    );
  }
  const allowedPrefixes = kind === 'read_only' ? SAFE_READ_ONLY_CONTAINER_PREFIXES : SAFE_READ_WRITE_CONTAINER_PREFIXES;
  const ok = allowedPrefixes.some(prefix => normalized === prefix || normalized.startsWith(`${prefix}/`));
  if (!ok) {
    throw new Error(`filesystem_policy.${kind} path is outside safe container prefixes: ${rawPath}`);
  }
  return normalized;
}

function validateHttpMethod(raw: unknown): string {
  const m = String(raw || '*').trim().toUpperCase();
  if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', '*'].includes(m)) {
    throw new Error(`Unsupported HTTP method in L7 rule: ${String(raw)}`);
  }
  return m;
}

function validateHttpPath(raw: unknown): string {
  const p = String(raw || '/**').trim();
  if (!p.startsWith('/') || p.includes('\0') || /\s/.test(p)) {
    throw new Error(`Invalid L7 HTTP path pattern: ${String(raw)}`);
  }
  return p;
}

function sanitizeBinaries(rawBinaries: unknown): Array<{ path: string }> | undefined {
  if (rawBinaries === undefined) return undefined;
  if (!Array.isArray(rawBinaries)) {
    throw new Error('network_policies.binaries must be an array');
  }
  if (rawBinaries.length > 32) {
    throw new Error('network_policies.binaries may contain at most 32 entries');
  }
  const normalized: Array<{ path: string }> = [];
  const seen = new Set<string>();
  for (const item of rawBinaries) {
    const p = typeof item === 'string' ? item.trim() : typeof (item as { path?: unknown })?.path === 'string' ? String((item as { path: string }).path).trim() : '';
    if (!p || !p.startsWith('/') || p.includes('..') || !/^\/[a-zA-Z0-9._/+@-]+$/.test(p)) {
      throw new Error(`Invalid binary path in network_policies: ${String(p)}`);
    }
    if (!seen.has(p)) {
      seen.add(p);
      normalized.push({ path: p });
    }
  }
  return normalized;
}

function sanitizeEndpoint(raw: Record<string, unknown>): NetworkEndpoint {
  if (raw.request_body_credential_rewrite !== undefined) {
    throw new Error('Subagent network_policies cannot set request_body_credential_rewrite');
  }
  const host = String(raw.host || '').trim();
  const hostErr = isDisallowedEgressHost(host);
  if (hostErr) throw new Error(hostErr);

  const port = raw.port === undefined ? 443 : Number(raw.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`Invalid port in network_policies for ${host}: ${String(raw.port)}`);
  }

  const protocol = raw.protocol === undefined ? 'rest' : String(raw.protocol).trim().toLowerCase();
  if (!['rest', 'tcp', 'grpc'].includes(protocol)) {
    throw new Error(`Unsupported protocol in network_policies for ${host}: ${protocol}`);
  }

  const enforcement = raw.enforcement === undefined ? 'enforce' : String(raw.enforcement).trim().toLowerCase();
  if (enforcement !== 'enforce') {
    throw new Error(`Subagent network_policies enforcement must be "enforce" (got "${enforcement}")`);
  }

  const endpoint: NetworkEndpoint = {
    host: host.toLowerCase(),
    port,
    protocol: protocol as 'rest' | 'tcp' | 'grpc',
    enforcement: 'enforce',
  };

  const rules: NonNullable<NetworkEndpoint['rules']> = [];
  if (Array.isArray(raw.rules)) {
    for (const r of raw.rules) {
      const allow = (r as { allow?: { method?: unknown; path?: unknown } })?.allow;
      if (!allow || typeof allow !== 'object') {
        throw new Error(`Invalid L7 rule entry for ${host}`);
      }
      rules.push({
        allow: {
          method: validateHttpMethod(allow.method),
          path: validateHttpPath(allow.path),
        },
      });
    }
  } else if (raw.method !== undefined || raw.path !== undefined) {
    rules.push({
      allow: {
        method: validateHttpMethod(raw.method),
        path: validateHttpPath(raw.path),
      },
    });
  }

  const denyRules: NonNullable<NetworkEndpoint['deny_rules']> = [];
  if (Array.isArray(raw.deny_rules)) {
    for (const d of raw.deny_rules) {
      if (!d || typeof d !== 'object') throw new Error(`Invalid L7 deny_rules entry for ${host}`);
      denyRules.push({
        method: validateHttpMethod((d as { method?: unknown }).method),
        path: validateHttpPath((d as { path?: unknown }).path),
      });
    }
  }

  if (rules.length > 0 || denyRules.length > 0) {
    if (rules.length > 0) endpoint.rules = rules;
    if (denyRules.length > 0) endpoint.deny_rules = denyRules;
  } else {
    const access = raw.access === undefined ? 'read-only' : String(raw.access).trim().toLowerCase();
    if (access !== 'read-only' && access !== 'read-write') {
      throw new Error(`Invalid access mode for ${host}: ${access}`);
    }
    endpoint.access = access;
  }

  return endpoint;
}

export function extractPolicyHostKeys(policy: OpenShellPolicy | null | undefined): Set<string> {
  const keys = new Set<string>();
  for (const netPol of Object.values(policy?.network_policies || {})) {
    for (const ep of netPol?.endpoints || []) {
      if (ep?.host) {
        keys.add(`${ep.host.toLowerCase()}:${ep.port ?? 443}`);
      }
    }
  }
  return keys;
}

function hostMatchesAllowlist(host: string, allowlist: string[]): boolean {
  const lower = host.toLowerCase();
  return allowlist.some(entry => {
    const pattern = entry.trim().toLowerCase();
    if (!pattern) return false;
    if (pattern.startsWith('*.')) {
      const suffix = pattern.slice(1);
      return lower.endsWith(suffix) && lower.length > suffix.length;
    }
    return lower === pattern;
  });
}

export function parseRawPolicyPayload(rawInput: string): Record<string, unknown> {
  if (typeof rawInput !== 'string' || !rawInput.trim()) {
    throw new Error('OpenShell policy payload cannot be empty');
  }
  if (rawInput.length > 32768) {
    throw new Error('OpenShell policy payload exceeds 32768 byte limit');
  }
  const trimmed = rawInput.trim();
  if (trimmed.startsWith('{')) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      throw new Error('Invalid JSON in subagent OpenShell policy');
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('Subagent OpenShell policy must be a JSON/YAML object');
    }
    return parsed as Record<string, unknown>;
  }

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'orca-subagent-yaml-'));
  const tmpFile = path.join(tmpDir, 'policy.yaml');
  try {
    fs.writeFileSync(tmpFile, rawInput, { mode: 0o600 });
    const jsonOut = execFileSync(resolveLocalBin('yq'), ['.', tmpFile], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 5000,
    });
    const parsed = JSON.parse(jsonOut);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('Subagent OpenShell YAML policy must deserialize to an object');
    }
    return parsed as Record<string, unknown>;
  } catch (err) {
    throw new Error(`Failed to parse YAML subagent policy: ${err instanceof Error ? err.message : String(err)}`);
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
  }
}

export function validateSubagentOpenShellPolicy(
  rawObj: Record<string, unknown>,
  options?: {
    parentOpenShellPolicy?: OpenShellPolicy | null;
    allowedEgressHosts?: string[];
  }
): OpenShellPolicy | null {
  if (rawObj.network_middlewares !== undefined || rawObj.networkMiddlewares !== undefined) {
    throw new Error('Subagent policy cannot override or disable network_middlewares');
  }
  if (rawObj.process !== undefined) {
    throw new Error('Subagent policy cannot override process execution identity');
  }
  if (rawObj.landlock !== undefined) {
    const ll = rawObj.landlock as { compatibility?: unknown };
    if (!ll || typeof ll !== 'object' || ll.compatibility !== 'hard_requirement') {
      throw new Error('Subagent policy cannot weaken landlock.compatibility from hard_requirement');
    }
  }

  const rawFs = (rawObj.filesystem_policy ?? rawObj.filesystemPolicy) as Record<string, unknown> | undefined;
  let hasFs = false;
  const filesystemPolicy: { read_only: string[]; read_write: string[] } = { read_only: [], read_write: [] };
  if (rawFs !== undefined) {
    if (!rawFs || typeof rawFs !== 'object' || Array.isArray(rawFs)) {
      throw new Error('filesystem_policy must be an object');
    }
    if (rawFs.include_workdir !== undefined) {
      throw new Error('Subagent policy cannot override filesystem_policy.include_workdir (use readPaths/writePaths)');
    }
    if (Array.isArray(rawFs.read_only)) {
      filesystemPolicy.read_only = rawFs.read_only.map(p => validateSafeContainerFsPath(String(p), 'read_only'));
      if (filesystemPolicy.read_only.length > 0) hasFs = true;
    }
    if (Array.isArray(rawFs.read_write)) {
      filesystemPolicy.read_write = rawFs.read_write.map(p => validateSafeContainerFsPath(String(p), 'read_write'));
      if (filesystemPolicy.read_write.length > 0) hasFs = true;
    }
  }

  const rawNet = (rawObj.network_policies ?? rawObj.networkPolicies) as Record<string, unknown> | undefined;
  const shorthandEndpoints = rawObj.endpoints;
  const networkPolicies: Record<string, NetworkPolicy> = {};
  let totalEndpoints = 0;

  if (rawNet !== undefined) {
    if (!rawNet || typeof rawNet !== 'object' || Array.isArray(rawNet)) {
      throw new Error('network_policies must be a map of policy rules');
    }
    for (const [rawKey, rawPol] of Object.entries(rawNet)) {
      if (rawKey.startsWith('_provider_')) {
        throw new Error(`Reserved _provider_ policy key is forbidden: ${rawKey}`);
      }
      if (!/^[a-zA-Z0-9_-]{1,64}$/.test(rawKey)) {
        throw new Error(`Invalid network policy key: ${rawKey}`);
      }
      if (!rawPol || typeof rawPol !== 'object' || Array.isArray(rawPol)) {
        throw new Error(`network_policies.${rawKey} must be an object`);
      }
      const polObj = rawPol as Record<string, unknown>;
      const epsRaw = polObj.endpoints;
      if (!Array.isArray(epsRaw) || epsRaw.length === 0) {
        throw new Error(`network_policies.${rawKey}.endpoints must be a non-empty array`);
      }
      const binaries = sanitizeBinaries(polObj.binaries);
      const endpoints: NetworkEndpoint[] = [];
      for (const epRaw of epsRaw) {
        if (!epRaw || typeof epRaw !== 'object' || Array.isArray(epRaw)) {
          throw new Error(`Invalid endpoint in network_policies.${rawKey}`);
        }
        totalEndpoints++;
        if (totalEndpoints > 32) {
          throw new Error('Subagent policy may define at most 32 network endpoints');
        }
        endpoints.push(sanitizeEndpoint(epRaw as Record<string, unknown>));
      }
      networkPolicies[rawKey] = {
        name: typeof polObj.name === 'string' && /^[a-zA-Z0-9_ .-]{1,64}$/.test(polObj.name) ? polObj.name : rawKey,
        ...(binaries && binaries.length > 0 ? { binaries } : {}),
        endpoints,
      };
    }
  }

  if (shorthandEndpoints !== undefined) {
    if (!Array.isArray(shorthandEndpoints)) {
      throw new Error('endpoints shorthand must be an array');
    }
    shorthandEndpoints.forEach((epRaw, idx) => {
      if (!epRaw || typeof epRaw !== 'object' || Array.isArray(epRaw)) {
        throw new Error(`Invalid endpoint at endpoints[${idx}]`);
      }
      totalEndpoints++;
      if (totalEndpoints > 32) {
        throw new Error('Subagent policy may define at most 32 network endpoints');
      }
      const obj = epRaw as Record<string, unknown>;
      const ep = sanitizeEndpoint(obj);
      const binaries = sanitizeBinaries(obj.binaries);
      const key = `subagent_${ep.host.replace(/[^a-zA-Z0-9]+/g, '_')}_${ep.port}_${idx}`;
      networkPolicies[key] = {
        name: key,
        ...(binaries && binaries.length > 0 ? { binaries } : {}),
        endpoints: [ep],
      };
    });
  }

  const hasNet = Object.keys(networkPolicies).length > 0;
  if (!hasFs && !hasNet) {
    return null;
  }

  // Enforce allowlist and monotonic attenuation against parent worker policy
  const parentNet = options?.parentOpenShellPolicy?.network_policies;
  const hasParentNetConstraint = Boolean(parentNet && Object.keys(parentNet).length > 0);
  const parentAllowedKeys = hasParentNetConstraint ? extractPolicyHostKeys(options?.parentOpenShellPolicy) : null;

  for (const netPol of Object.values(networkPolicies)) {
    for (const ep of netPol.endpoints) {
      if (options?.allowedEgressHosts && options.allowedEgressHosts.length > 0) {
        if (!hostMatchesAllowlist(ep.host, options.allowedEgressHosts)) {
          throw new Error(`Host "${ep.host}" is not permitted by delegation grant allowedEgressHosts`);
        }
      }
      if (parentAllowedKeys && !parentAllowedKeys.has(`${ep.host}:${ep.port}`)) {
        throw new Error(`Endpoint "${ep.host}:${ep.port}" exceeds parent worker OpenShell network policy`);
      }
    }
  }

  return {
    version: 1,
    landlock: { compatibility: 'hard_requirement' },
    ...(hasFs ? { filesystem_policy: filesystemPolicy } : {}),
    ...(hasNet ? { network_policies: networkPolicies } : {}),
  };
}

export function resolveSubagentCombinedPolicy(params: {
  projectRoot: string;
  readRaw: string | null;
  writeRaw: string | null;
  openshellPolicyRaw: string | null;
  parentFileScope?: WorkspaceFileScope | null;
  parentOpenShellPolicy?: OpenShellPolicy | null;
  allowedEgressHosts?: string[];
  allowDynamicPolicies?: boolean;
}): {
  fileScope: WorkspaceFileScope | null;
  openshellPolicy: OpenShellPolicy | null;
} {
  let effectiveReadRaw = params.readRaw;
  let effectiveWriteRaw = params.writeRaw;
  let openshellPolicy: OpenShellPolicy | null = null;

  if (params.openshellPolicyRaw !== null) {
    const rawObj = parseRawPolicyPayload(params.openshellPolicyRaw);
    const rawRead = rawObj.readPaths ?? rawObj.read_paths;
    const rawWrite = rawObj.writePaths ?? rawObj.write_paths;
    if (effectiveReadRaw === null && rawRead !== undefined) {
      effectiveReadRaw = Array.isArray(rawRead) ? JSON.stringify(rawRead) : String(rawRead);
    }
    if (effectiveWriteRaw === null && rawWrite !== undefined) {
      effectiveWriteRaw = Array.isArray(rawWrite) ? JSON.stringify(rawWrite) : String(rawWrite);
    }
    const candidateOpenShell = validateSubagentOpenShellPolicy(rawObj, {
      parentOpenShellPolicy: params.parentOpenShellPolicy,
      allowedEgressHosts: params.allowedEgressHosts,
    });
    if (candidateOpenShell) {
      if (params.allowDynamicPolicies === false) {
        throw new Error('Dynamic OpenShell policies are disabled by the delegation grant');
      }
      openshellPolicy = candidateOpenShell;
    } else if (params.parentOpenShellPolicy) {
      openshellPolicy = JSON.parse(JSON.stringify(params.parentOpenShellPolicy)) as OpenShellPolicy;
    }
  } else if (params.parentOpenShellPolicy) {
    // Inherit parent worker's scoped OpenShell policy if grandchild does not provide one
    openshellPolicy = JSON.parse(JSON.stringify(params.parentOpenShellPolicy)) as OpenShellPolicy;
  }

  const fileScope = resolveSubagentFileScope(
    params.projectRoot,
    effectiveReadRaw,
    effectiveWriteRaw,
    params.parentFileScope
  );

  return { fileScope, openshellPolicy };
}

function ensureGitExcludeEntry(worktreePath: string, pattern: string): void {
  try {
    const commonDir = execFileSync('git', ['rev-parse', '--git-common-dir'], {
      cwd: worktreePath,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 3000,
    }).trim();
    if (!commonDir) return;
    const resolvedCommonDir = path.isAbsolute(commonDir)
      ? commonDir
      : path.resolve(worktreePath, commonDir);
    const infoDir = path.join(resolvedCommonDir, 'info');
    const excludeFile = path.join(infoDir, 'exclude');
    fs.mkdirSync(infoDir, { recursive: true });
    const existing = fs.existsSync(excludeFile) ? fs.readFileSync(excludeFile, 'utf8') : '';
    const lines = existing.split(/\r?\n/);
    if (!lines.includes(pattern)) {
      const prefix = existing && !existing.endsWith('\n') ? '\n' : '';
      fs.writeFileSync(excludeFile, `${existing}${prefix}${pattern}\n`);
    }
  } catch {
    // Non-git directory or git missing — safe to ignore
  }
}

export function installTempWorktreePolicy(
  worktreePath: string,
  policy: OpenShellPolicy,
  scopeId = crypto.randomUUID().slice(0, 8)
): { filePath: string; createdDirs: string[] } {
  const agentsDir = path.join(worktreePath, '.agents');
  const policiesDir = path.join(agentsDir, 'policies');
  const createdDirs: string[] = [];
  if (!fs.existsSync(agentsDir)) createdDirs.push(agentsDir);
  if (!fs.existsSync(policiesDir)) createdDirs.push(policiesDir);
  fs.mkdirSync(policiesDir, { recursive: true });
  ensureGitExcludeEntry(worktreePath, '.agents/policies/.orca-openshell-temp-*.json');

  const safeId = scopeId.replace(/[^a-zA-Z0-9_-]/g, '') || crypto.randomUUID().slice(0, 8);
  const filePath = path.join(policiesDir, `.orca-openshell-temp-${safeId}.json`);
  // Write pure OpenShell policy JSON without custom keys so openshell CLI schema validation stays strict
  const sanitized: OpenShellPolicy = {
    version: 1,
    landlock: { compatibility: 'hard_requirement' },
    ...(policy.filesystem_policy ? { filesystem_policy: policy.filesystem_policy } : {}),
    ...(policy.network_policies ? { network_policies: policy.network_policies } : {}),
  };
  const tmp = `${filePath}.${process.pid}.${crypto.randomUUID()}`;
  fs.writeFileSync(tmp, JSON.stringify(sanitized, null, 2) + '\n', { mode: 0o600 });
  fs.renameSync(tmp, filePath);
  return { filePath, createdDirs };
}

export function removeTempWorktreePolicy(filePath?: string | null, createdDirs?: string[] | null): void {
  if (filePath) {
    try {
      if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    } catch {}
  }
  if (createdDirs && createdDirs.length > 0) {
    // Remove in reverse order (policies dir first, then .agents dir) only if empty
    for (const dir of [...createdDirs].reverse()) {
      try {
        if (fs.existsSync(dir) && fs.readdirSync(dir).length === 0) {
          fs.rmdirSync(dir);
        }
      } catch {}
    }
  }
}

