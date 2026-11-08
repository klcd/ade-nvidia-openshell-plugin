import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import type { OpenShellPolicy } from './types.js';
import { logDebug, USER_HOME } from './config.js';

export function parsePolicyFile(filePath: string): OpenShellPolicy | null {
  if (!fs.existsSync(filePath)) {
    return null;
  }
  try {
    if (filePath.endsWith('.json')) {
      const content = fs.readFileSync(filePath, 'utf-8');
      return JSON.parse(content) as OpenShellPolicy;
    }
    if (filePath.endsWith('.yaml') || filePath.endsWith('.yml')) {
      try {
        const jsonOut = execFileSync('yq', ['.', filePath], {
          encoding: 'utf-8',
          stdio: ['ignore', 'pipe', 'ignore'],
        });
        return JSON.parse(jsonOut) as OpenShellPolicy;
      } catch {
        // Fallback simple line-based YAML extractor for basic policies if yq missing
      }
    }
  } catch (err) {
    logDebug(`Failed to parse policy file ${filePath}: ${err}`);
  }
  return null;
}

export function mergePolicies(policyDirs: string[]): OpenShellPolicy | null {
  const merged: OpenShellPolicy = {
    version: 1,
    filesystem_policy: {
      include_workdir: true,
      read_only: [],
      read_write: [],
    },
    landlock: {
      compatibility: 'best_effort',
    },
    network_policies: {},
    network_middlewares: {},
  };

  const seenRo = new Set<string>();
  const seenRw = new Set<string>();
  let foundAny = false;

  for (const pdir of policyDirs) {
    if (!fs.existsSync(pdir) || !fs.statSync(pdir).isDirectory()) {
      continue;
    }
    const entries = fs.readdirSync(pdir);
    for (const file of entries) {
      if (!file.endsWith('.json') && !file.endsWith('.yaml') && !file.endsWith('.yml')) {
        continue;
      }
      const fullPath = path.join(pdir, file);
      const data = parsePolicyFile(fullPath);
      if (!data) {
        continue;
      }
      foundAny = true;

      const fsp = data.filesystem_policy;
      if (fsp) {
        if (fsp.include_workdir !== undefined) {
          merged.filesystem_policy!.include_workdir = fsp.include_workdir;
        }
        for (const ro of fsp.read_only || []) {
          if (!seenRo.has(ro)) {
            seenRo.add(ro);
            merged.filesystem_policy!.read_only.push(ro);
          }
        }
        for (const rw of fsp.read_write || []) {
          if (!seenRw.has(rw)) {
            seenRw.add(rw);
            merged.filesystem_policy!.read_write.push(rw);
          }
        }
      }

      if (data.landlock) {
        Object.assign(merged.landlock!, data.landlock);
      }

      if (data.process) {
        merged.process ??= {};
        Object.assign(merged.process, data.process);
      }

      if (data.network_policies) {
        for (const [k, v] of Object.entries(data.network_policies)) {
          if (!k.startsWith('_provider_')) {
            merged.network_policies![k] = v;
          }
        }
      }

      if (data.network_middlewares) {
        Object.assign(merged.network_middlewares!, data.network_middlewares);
      }
    }
  }

  return foundAny ? merged : null;
}

export function mergeTwoPolicies(base: OpenShellPolicy, overlay: OpenShellPolicy | null): OpenShellPolicy {
  if (!overlay) return base;
  const merged: OpenShellPolicy = {
    version: base.version ?? 1,
    filesystem_policy: {
      include_workdir: overlay.filesystem_policy?.include_workdir ?? base.filesystem_policy?.include_workdir ?? true,
      read_only: [...new Set([...(base.filesystem_policy?.read_only || []), ...(overlay.filesystem_policy?.read_only || [])])],
      read_write: [...new Set([...(base.filesystem_policy?.read_write || []), ...(overlay.filesystem_policy?.read_write || [])])],
    },
    landlock: {
      compatibility: base.landlock?.compatibility ?? overlay.landlock?.compatibility ?? 'best_effort',
      ...(base.landlock || {}),
      ...(overlay.landlock || {}),
    },
    ...(base.process || overlay.process ? { process: { ...(base.process || {}), ...(overlay.process || {}) } } : {}),
    network_policies: {
      ...(base.network_policies || {}),
      ...Object.fromEntries(Object.entries(overlay.network_policies || {}).filter(([k]) => !k.startsWith('_provider_'))),
    },
    network_middlewares: {
      ...(base.network_middlewares || {}),
      ...(overlay.network_middlewares || {}),
    },
  };
  return merged;
}

export function discoverAndMergePolicies(projectRoot: string): OpenShellPolicy | null {
  const globalPolicies = path.join(USER_HOME, '.agents', 'policies');
  const projectPolicies = path.join(projectRoot, '.agents', 'policies');
  return mergePolicies([globalPolicies, projectPolicies]);
}
