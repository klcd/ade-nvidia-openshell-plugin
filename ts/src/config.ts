import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';

export const USER_HOME = os.homedir();
export const DEBUG_LOG_PATH = path.join(USER_HOME, '.orca', 'openshell-bridge.log');

export function logDebug(message: string): void {
  try {
    fs.mkdirSync(path.dirname(DEBUG_LOG_PATH), { recursive: true });
    const timestamp = new Date().toISOString().replace('T', ' ').slice(0, 19);
    fs.appendFileSync(DEBUG_LOG_PATH, `[${timestamp}] [PID ${process.pid}] ${message}\n`);
  } catch {
    // Ignore logging failures to never block the main bridge
  }
}

/**
 * Discovers the git project root or falls back to process.cwd()
 */
export function detectProjectRoot(cwd = process.cwd()): string {
  try {
    const stdout = execFileSync('git', ['-C', cwd, 'rev-parse', '--show-toplevel'], {
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    if (stdout.trim()) {
      return stdout.trim();
    }
  } catch {
    // Not a git repository
  }
  return cwd;
}

/**
 * Generates an OpenShell sandbox identifier conforming to the <=19 char requirement.
 */
export function generateSandboxName(prefix: string, projectName: string, pid = process.pid): string {
  const safeProj = projectName.replace(/[^a-zA-Z0-9_-]/g, '-').toLowerCase();
  const truncated = safeProj.slice(0, 8).replace(/^-+|-+$/g, '') || 'ws';
  const suffix = `${(pid % 1000).toString(36)}${randomBytes(3).toString('hex')}`;
  return `${prefix}-${truncated.slice(0, 6)}-${suffix}`.slice(0, 19);
}

/**
 * Finds the native host binary for fallback and fast paths.
 */
export function findHostBinary(name: string): string | null {
  const pathDirs = (process.env.PATH || '').split(path.delimiter);
  for (const dir of pathDirs) {
    const candidate = path.join(dir, name);
    try {
      if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
        const real = fs.realpathSync(candidate);
        if (!real.endsWith('-bridge.py') && !real.endsWith('-box') && !real.endsWith('.bundle.js')) {
          return candidate;
        }
      }
    } catch {
      // Continue
    }
  }

  const user = process.env.USER || '';
  const standardFallbacks = [
    `/etc/profiles/per-user/${user}/bin/${name}`,
    `/run/current-system/sw/bin/${name}`,
    `/opt/homebrew/bin/${name}`,
    `/usr/local/bin/${name}`,
    `/usr/bin/${name}`,
  ];

  for (const candidate of standardFallbacks) {
    try {
      if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
        return candidate;
      }
    } catch {
      // Continue
    }
  }

  return null;
}
