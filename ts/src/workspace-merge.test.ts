import { test, expect } from 'bun:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { mergeWorkspace, snapshotWorkspace } from './workspace-merge.js';

test('Orca sync applies sandbox edits but preserves concurrent host edits', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'orca-merge-test-'));
  const host = path.join(root, 'host');
  const sandbox = path.join(root, 'sandbox');
  const conflicts = path.join(root, 'conflicts');
  try {
    fs.mkdirSync(host);
    fs.writeFileSync(path.join(host, 'safe.txt'), 'before');
    fs.writeFileSync(path.join(host, 'conflict.txt'), 'before');
    fs.writeFileSync(path.join(host, 'unchanged.txt'), 'before');
    fs.mkdirSync(path.join(host, '.git'));
    fs.writeFileSync(path.join(host, '.git', 'config'), 'host git');
    const baseline = snapshotWorkspace(host);
    fs.cpSync(host, sandbox, { recursive: true });
    fs.writeFileSync(path.join(sandbox, 'safe.txt'), 'sandbox edit');
    fs.writeFileSync(path.join(sandbox, 'conflict.txt'), 'sandbox edit');
    fs.writeFileSync(path.join(host, 'conflict.txt'), 'host edit');
    fs.writeFileSync(path.join(host, 'unchanged.txt'), 'host edit');
    fs.writeFileSync(path.join(sandbox, '.git', 'config'), 'sandbox git');
    const result = mergeWorkspace(host, sandbox, baseline, null, conflicts);
    expect(result.applied).toBe(1);
    expect(result.conflicts).toEqual(['conflict.txt']);
    expect(fs.readFileSync(path.join(host, 'safe.txt'), 'utf8')).toBe('sandbox edit');
    expect(fs.readFileSync(path.join(host, 'conflict.txt'), 'utf8')).toBe('host edit');
    expect(fs.readFileSync(path.join(host, 'unchanged.txt'), 'utf8')).toBe('host edit');
    expect(fs.readFileSync(path.join(host, '.git', 'config'), 'utf8')).toBe('host git');
    expect(fs.readFileSync(path.join(conflicts, 'conflict.txt'), 'utf8')).toBe('sandbox edit');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
