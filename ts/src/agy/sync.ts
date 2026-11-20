import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { logDebug } from '../config.js';
import { isRelativePathAllowed } from '../sandbox-scope.js';
import { shellQuote, type AgyChatSandboxState } from './state.js';

export function isSshControlAlive(state: AgyChatSandboxState): boolean {
  if (!fs.existsSync(state.sshConfigPath) || !fs.existsSync(state.sshControlPath)) {
    return false;
  }
  try {
    execFileSync(
      'ssh',
      ['-S', state.sshControlPath, '-F', state.sshConfigPath, '-O', 'check', state.sshHost],
      { stdio: ['ignore', 'ignore', 'ignore'], timeout: 2000 }
    );
    return true;
  } catch {
    return false;
  }
}

export function syncHostDeltaToSandbox(state: AgyChatSandboxState, sessionDir: string): void {
  const stampFile = path.join(sessionDir, 'host-sync.stamp');
  if (!fs.existsSync(stampFile)) {
    fs.writeFileSync(stampFile, '');
    return;
  }
  try {
    const findOut = execFileSync(
      'find',
      [
        '.',
        '(',
        '-name', '.git',
        '-o', '-name', 'node_modules',
        '-o', '-name', '.next',
        '-o', '-name', 'target',
        ')',
        '-prune',
        '-o',
        '-type', 'f',
        '-newer', stampFile,
        '-print',
      ],
      {
        cwd: state.projectRoot,
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
        timeout: 4000,
      }
    ).trim();

    if (!findOut) return;
    const files = findOut
      .split(/\r?\n/)
      .filter(Boolean)
      .filter(f => {
        if (state.stagedUploadPaths === undefined || state.stagedUploadPaths === null) return true;
        const rel = f.replace(/^\.\//, '');
        return isRelativePathAllowed(rel, state.stagedUploadPaths);
      });
    if (files.length === 0) return;

    const listFile = path.join(sessionDir, `host-delta-${process.pid}.list`);
    fs.writeFileSync(listFile, files.join('\n') + '\n');
    try {
      const tarBuf = execFileSync('tar', ['-cf', '-', '-C', state.projectRoot, '-T', listFile], {
        stdio: ['ignore', 'pipe', 'ignore'],
        maxBuffer: 64 * 1024 * 1024,
        timeout: 10000,
      });
      execFileSync(
        'ssh',
        [
          '-T',
          '-S', state.sshControlPath,
          '-F', state.sshConfigPath,
          state.sshHost,
          `tar -xf - -C ${shellQuote(state.containerRoot)} && touch /tmp/.orca_sync_marker`,
        ],
        {
          input: tarBuf,
          stdio: ['pipe', 'ignore', 'ignore'],
          timeout: 10000,
        }
      );
      const now = new Date();
      fs.utimesSync(stampFile, now, now);
    } finally {
      try {
        fs.unlinkSync(listFile);
      } catch {}
    }
  } catch (err) {
    logDebug(`Antigravity host->sandbox delta sync warning: ${err}`);
  }
}

export function syncSandboxDeltaToHost(state: AgyChatSandboxState, sessionDir: string): void {
  if (state.writePaths && state.writePaths.length === 0) return;
  const stampFile = path.join(sessionDir, 'host-sync.stamp');
  try {
    const remoteScript = [
      `cd ${shellQuote(state.containerRoot)} || exit 0`,
      `if [ ! -f /tmp/.orca_sync_marker ]; then touch /tmp/.orca_sync_marker; exit 0; fi`,
      `find . \\( -name node_modules -o -name .next -o -name target \\) -prune -o -type f -newer /tmp/.orca_sync_marker -print > /tmp/.orca_changed_files`,
      `touch /tmp/.orca_sync_marker`,
      `if [ -s /tmp/.orca_changed_files ]; then tar -cf - -T /tmp/.orca_changed_files; fi`,
      `rm -f /tmp/.orca_changed_files`,
    ].join('; ');

    const tarOut = execFileSync(
      'ssh',
      ['-T', '-S', state.sshControlPath, '-F', state.sshConfigPath, state.sshHost, remoteScript],
      {
        stdio: ['ignore', 'pipe', 'ignore'],
        maxBuffer: 64 * 1024 * 1024,
        timeout: 15000,
      }
    );

    if (tarOut && tarOut.length > 0) {
      if (state.writePaths) {
        const unpackDir = fs.mkdtempSync(path.join(os.tmpdir(), `agy-sync-scope-${process.pid}-`));
        try {
          execFileSync('tar', ['-xf', '-', '-C', unpackDir], {
            input: tarOut,
            stdio: ['pipe', 'ignore', 'ignore'],
            timeout: 10000,
          });
          const copyAllowed = (dir: string, relBase = '') => {
            for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
              if (entry.name === '.git') continue;
              const rel = relBase ? path.join(relBase, entry.name) : entry.name;
              const src = path.join(dir, entry.name);
              const stat = fs.lstatSync(src);
              if (stat.isSymbolicLink()) continue;
              if (stat.isDirectory()) {
                copyAllowed(src, rel);
              } else if (stat.isFile() && isRelativePathAllowed(rel, state.writePaths!)) {
                const dst = path.join(state.projectRoot, rel);
                fs.mkdirSync(path.dirname(dst), { recursive: true });
                fs.copyFileSync(src, dst);
                fs.chmodSync(dst, stat.mode & 0o777);
              }
            }
          };
          copyAllowed(unpackDir);
        } finally {
          fs.rmSync(unpackDir, { recursive: true, force: true });
        }
      } else {
        execFileSync('tar', ['-xf', '-', '-C', state.projectRoot], {
          input: tarOut,
          stdio: ['pipe', 'ignore', 'ignore'],
          timeout: 10000,
        });
      }
      const now = new Date();
      if (fs.existsSync(stampFile)) {
        fs.utimesSync(stampFile, now, now);
      } else {
        fs.writeFileSync(stampFile, '');
      }
    }
  } catch (err) {
    logDebug(`Antigravity sandbox->host delta sync warning: ${err}`);
  }
}
