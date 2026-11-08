import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';

type Entry = { kind: 'file' | 'link'; fingerprint: string };
export type WorkspaceSnapshot = Map<string, Entry>;
const key = (file: string): string => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
function entryAt(file: string): Entry | undefined {
  try {
    const stat = fs.lstatSync(file);
    if (stat.isFile()) return { kind: 'file', fingerprint: `${key(file)}:${stat.mode & 0o777}` };
    if (stat.isSymbolicLink()) return { kind: 'link', fingerprint: fs.readlinkSync(file) };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }
  return undefined;
}

/** Capture only files, never traverse symlinks or Git metadata. */
export function snapshotWorkspace(root: string): WorkspaceSnapshot {
  const entries: WorkspaceSnapshot = new Map();
  function visit(dir: string, relative: string): void {
    for (const item of fs.readdirSync(dir, { withFileTypes: true })) {
      if (relative === '' && item.name === '.git') continue;
      const rel = relative ? path.join(relative, item.name) : item.name;
      const absolute = path.join(dir, item.name);
      const stat = fs.lstatSync(absolute);
      if (stat.isDirectory()) visit(absolute, rel);
      else if (stat.isFile()) entries.set(rel, { kind: 'file', fingerprint: `${key(absolute)}:${stat.mode & 0o777}` });
      else if (stat.isSymbolicLink()) entries.set(rel, { kind: 'link', fingerprint: fs.readlinkSync(absolute) });
    }
  }
  visit(root, '');
  return entries;
}

function allowed(relative: string, writePaths: string[] | null): boolean {
  return writePaths === null || writePaths.some(scope => relative === scope || relative.startsWith(`${scope}${path.sep}`));
}

export function mergeWorkspace(
  hostRoot: string,
  sandboxRoot: string,
  baseline: WorkspaceSnapshot,
  writePaths: string[] | null,
  conflictRoot = path.join(os.homedir(), '.orca', 'openshell-conflicts'),
): { applied: number; conflicts: string[] } {
  const sandbox = snapshotWorkspace(sandboxRoot);
  const host = snapshotWorkspace(hostRoot);
  const conflicts: string[] = [];
  let applied = 0;
  for (const relative of new Set([...baseline.keys(), ...sandbox.keys()])) {
    if (!allowed(relative, writePaths)) continue;
    const before = baseline.get(relative);
    const after = sandbox.get(relative);
    if (JSON.stringify(before) === JSON.stringify(after)) continue;
    const destination = path.join(hostRoot, relative);
    const current = host.get(relative);
    if (JSON.stringify(current) !== JSON.stringify(before) || after?.kind === 'link') {
      conflicts.push(relative);
      if (after?.kind === 'file') {
        const destination = path.join(conflictRoot, relative);
        fs.mkdirSync(path.dirname(destination), { recursive: true, mode: 0o700 });
        fs.copyFileSync(path.join(sandboxRoot, relative), destination);
      }
      continue;
    }
    if (JSON.stringify(entryAt(destination)) !== JSON.stringify(before)) {
      conflicts.push(relative);
      continue;
    }
    if (!after) {
      if (current?.kind === 'file') fs.unlinkSync(destination);
      applied++;
    } else if (after.kind === 'file') {
      fs.mkdirSync(path.dirname(destination), { recursive: true });
      const temp = `${destination}.openshell-${crypto.randomUUID()}`;
      fs.copyFileSync(path.join(sandboxRoot, relative), temp);
      fs.chmodSync(temp, fs.statSync(path.join(sandboxRoot, relative)).mode & 0o777);
      fs.renameSync(temp, destination);
      applied++;
    }
  }
  return { applied, conflicts };
}
