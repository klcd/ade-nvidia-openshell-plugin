import { describe, expect, test } from 'bun:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  buildStagedGitConfig,
  getDefaultSandboxEnabled,
  isSandboxModeEnabled,
  setDefaultSandboxEnabled,
} from './config';

describe('isSandboxModeEnabled per-worktree, child inheritance, and configurable default state', () => {
  test('is off by default for unconfigured worktrees and supports configurable defaultEnabled', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-box-default-mode-test-'));
    const wtA = path.join(dir, 'repo-a');
    const wtB = path.join(dir, 'repo-b');
    const wtC = path.join(dir, 'repo-c');
    const gitChild = path.join(dir, 'repo-a-feature-wt');
    const gitChildSubdir = path.join(gitChild, 'src', 'nested');
    const orcaChild = path.join(dir, 'repo-a-orca-child');
    const orcaChildSubdir = path.join(orcaChild, 'packages', 'api');

    fs.mkdirSync(path.join(wtA, '.git', 'worktrees', 'feature-wt'), { recursive: true });
    fs.mkdirSync(wtB, { recursive: true });
    fs.mkdirSync(wtC, { recursive: true });
    fs.mkdirSync(gitChildSubdir, { recursive: true });
    fs.mkdirSync(orcaChildSubdir, { recursive: true });
    fs.writeFileSync(
      path.join(gitChild, '.git'),
      `gitdir: ${path.join(wtA, '.git', 'worktrees', 'feature-wt')}\n`
    );

    const modeFile = path.join(dir, 'sandbox-mode.json');
    const prevMode = process.env.ORCA_OPENSHELL_MODE_FILE;
    const prevEnvDef = process.env.ORCA_OPENSHELL_DEFAULT_ENABLED;
    process.env.ORCA_OPENSHELL_MODE_FILE = modeFile;
    delete process.env.ORCA_OPENSHELL_DEFAULT_ENABLED;
    try {
      // 1. With no config file, sandboxing is off by default
      expect(getDefaultSandboxEnabled(dir)).toBe(false);
      expect(isSandboxModeEnabled(dir, wtA)).toBe(false);
      expect(isSandboxModeEnabled(dir, wtB)).toBe(false);

      // 2. Enabling wtA explicitly enables wtA and its git/Orca children while leaving unconfigured wtB off
      fs.writeFileSync(
        modeFile,
        JSON.stringify(
          {
            worktrees: {
              [wtA]: { enabled: true },
              [wtC]: { enabled: false },
            },
            parentPaths: {
              [orcaChild]: wtA,
            },
          },
          null,
          2
        )
      );

      expect(isSandboxModeEnabled(dir, wtA)).toBe(true);
      expect(isSandboxModeEnabled(dir, gitChild)).toBe(true);
      expect(isSandboxModeEnabled(dir, gitChildSubdir)).toBe(true);
      expect(isSandboxModeEnabled(dir, orcaChild)).toBe(true);
      expect(isSandboxModeEnabled(dir, orcaChildSubdir)).toBe(true);
      expect(isSandboxModeEnabled(dir, '', `repo-a::${gitChild}`)).toBe(true);
      // Unconfigured wtB falls back to default (false)
      expect(isSandboxModeEnabled(dir, wtB)).toBe(false);
      expect(isSandboxModeEnabled(dir, '', `repo-b::${wtB}`)).toBe(false);

      // 3. Changing global default to ON enables unconfigured wtB while preserving explicit wtC=false
      setDefaultSandboxEnabled(true, dir);
      expect(getDefaultSandboxEnabled(dir)).toBe(true);
      expect(isSandboxModeEnabled(dir, wtB)).toBe(true);
      expect(isSandboxModeEnabled(dir, wtC)).toBe(false);

      // 4. Environment variable ORCA_OPENSHELL_DEFAULT_ENABLED overrides the default for unconfigured worktrees
      process.env.ORCA_OPENSHELL_DEFAULT_ENABLED = 'off';
      expect(getDefaultSandboxEnabled(dir)).toBe(false);
      expect(isSandboxModeEnabled(dir, wtB)).toBe(false);
      expect(isSandboxModeEnabled(dir, wtA)).toBe(true);
    } finally {
      if (prevMode === undefined) delete process.env.ORCA_OPENSHELL_MODE_FILE;
      else process.env.ORCA_OPENSHELL_MODE_FILE = prevMode;
      if (prevEnvDef === undefined) delete process.env.ORCA_OPENSHELL_DEFAULT_ENABLED;
      else process.env.ORCA_OPENSHELL_DEFAULT_ENABLED = prevEnvDef;
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('buildStagedGitConfig rewrites SSH remotes to HTTPS and propagates author identity', () => {
    const gitConfig = buildStagedGitConfig(undefined, {
      userName: 'Cedric K.',
      userEmail: 'cedric@example.com',
    });
    expect(gitConfig).toContain('[safe]\n\tdirectory = *');
    expect(gitConfig).toContain('[url "https://github.com/"]\n\tinsteadOf = git@github.com:\n\tinsteadOf = ssh://git@github.com/');
    expect(gitConfig).toContain('[url "https://gitlab.com/"]\n\tinsteadOf = git@gitlab.com:\n\tinsteadOf = ssh://git@gitlab.com/');
    expect(gitConfig).toContain('[user]\n\tname = "Cedric K."\n\temail = "cedric@example.com"');
  });

  test('recovers cleanly from corrupted JSON state file by moving broken file aside', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-box-corrupt-json-test-'));
    const modeFile = path.join(dir, 'sandbox-mode.json');
    const prevMode = process.env.ORCA_OPENSHELL_MODE_FILE;
    process.env.ORCA_OPENSHELL_MODE_FILE = modeFile;
    try {
      fs.writeFileSync(modeFile, '{invalid-json-broken', 'utf8');
      expect(getDefaultSandboxEnabled(dir)).toBe(false);
      const filesAfterRead = fs.readdirSync(dir);
      expect(filesAfterRead.some(f => f.startsWith('sandbox-mode.json.broken-'))).toBe(true);

      setDefaultSandboxEnabled(true, dir);
      expect(getDefaultSandboxEnabled(dir)).toBe(true);
    } finally {
      if (prevMode === undefined) delete process.env.ORCA_OPENSHELL_MODE_FILE;
      else process.env.ORCA_OPENSHELL_MODE_FILE = prevMode;
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
