import { describe, expect, test } from 'bun:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { isSandboxModeEnabled } from './config';

describe('isSandboxModeEnabled per-worktree and child inheritance', () => {
  test('isolates worktrees and inherits parent worktree settings for git worktrees, Orca children, and subdirectories', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-box-mode-test-'));
    const wtA = path.join(dir, 'repo-a');
    const wtB = path.join(dir, 'repo-b');
    const gitChild = path.join(dir, 'repo-a-feature-wt');
    const gitChildSubdir = path.join(gitChild, 'src', 'nested');
    const orcaChild = path.join(dir, 'repo-a-orca-child');
    const orcaChildSubdir = path.join(orcaChild, 'packages', 'api');

    fs.mkdirSync(path.join(wtA, '.git', 'worktrees', 'feature-wt'), { recursive: true });
    fs.mkdirSync(wtB, { recursive: true });
    fs.mkdirSync(gitChildSubdir, { recursive: true });
    fs.mkdirSync(orcaChildSubdir, { recursive: true });
    fs.writeFileSync(
      path.join(gitChild, '.git'),
      `gitdir: ${path.join(wtA, '.git', 'worktrees', 'feature-wt')}\n`
    );

    const modeFile = path.join(dir, 'sandbox-mode.json');
    fs.writeFileSync(
      modeFile,
      JSON.stringify(
        {
          worktrees: {
            [wtA]: { enabled: false },
          },
          parentPaths: {
            [orcaChild]: wtA,
          },
        },
        null,
        2
      )
    );

    const prevMode = process.env.ORCA_OPENSHELL_MODE_FILE;
    process.env.ORCA_OPENSHELL_MODE_FILE = modeFile;
    try {
      expect(isSandboxModeEnabled(dir, wtA)).toBe(false);
      expect(isSandboxModeEnabled(dir, wtB)).toBe(true);
      expect(isSandboxModeEnabled(dir, gitChild)).toBe(false);
      expect(isSandboxModeEnabled(dir, gitChildSubdir)).toBe(false);
      expect(isSandboxModeEnabled(dir, orcaChild)).toBe(false);
      expect(isSandboxModeEnabled(dir, orcaChildSubdir)).toBe(false);
      expect(isSandboxModeEnabled(dir, '', `repo-a::${gitChild}`)).toBe(false);
      expect(isSandboxModeEnabled(dir, '', `repo-b::${wtB}`)).toBe(true);
    } finally {
      if (prevMode === undefined) delete process.env.ORCA_OPENSHELL_MODE_FILE;
      else process.env.ORCA_OPENSHELL_MODE_FILE = prevMode;
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
