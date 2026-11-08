import { describe, expect, test } from 'bun:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { DelegationBroker, readGrant, writeGrant } from './delegation.js';

describe('Orca delegation authorization', () => {
  test('requires an exact host-side terminal and workspace grant', () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'orca-delegation-test-'));
    const old = process.env.OPENSHELL_BRIDGE_DELEGATION_HOME;
    process.env.OPENSHELL_BRIDGE_DELEGATION_HOME = home;
    try {
      const broker = new DelegationBroker('sandbox', 'terminal-1', 'repo::/workspace', '/workspace');
      expect(broker.dispatch(['orchestration', 'worker-start', '--spec', 'Task']).code).toBe(77);
      writeGrant({ terminal: 'terminal-1', workspace: 'id:repo::/workspace', agents: ['codex'], maxWorkers: 2, depth: 0, maxDepth: 0 });
      expect(readGrant('terminal-1', 'repo::/workspace')).not.toBeNull();
      expect(readGrant('terminal-1', 'other::/workspace')).toBeNull();
      expect(new DelegationBroker('sandbox', 'terminal-2', 'repo::/workspace', '/workspace').dispatch(['orchestration', 'check']).code).toBe(77);
      expect(broker.dispatch(['orchestration', 'worker-start', '--spec', 'Task']).stderr).toContain('limit');
    } finally {
      if (old === undefined) delete process.env.OPENSHELL_BRIDGE_DELEGATION_HOME;
      else process.env.OPENSHELL_BRIDGE_DELEGATION_HOME = old;
      fs.rmSync(home, { recursive: true, force: true });
    }
  });

  test('rejects privileged placement, identity spoofing, and unsupported commands', () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'orca-delegation-test-'));
    const old = process.env.OPENSHELL_BRIDGE_DELEGATION_HOME;
    process.env.OPENSHELL_BRIDGE_DELEGATION_HOME = home;
    try {
      writeGrant({ terminal: 'terminal-1', workspace: 'id:repo::/workspace', agents: ['codex'], maxWorkers: 2, depth: 0, maxDepth: 1 });
      const broker = new DelegationBroker('sandbox', 'terminal-1', 'repo::/workspace', '/workspace');
      for (const args of [
        ['agent', 'launch', '--agent', 'codex'],
        ['orchestration', 'worker-start', '--spec', 'Task', '--worktree', 'new-child'],
        ['orchestration', 'worker-start', '--spec', 'Task', '--on', 'remote'],
        ['orchestration', 'worker-start', '--spec', 'Task', '--from', 'another-terminal'],
        ['orchestration', 'worker-start', '--spec', 'Task', '--agent', 'opencode'],
        ['orchestration', 'worker-start', '--spec', 'Task', '--spec', 'Other'],
        ['orchestration', 'worker-start', '--spec', 'Task', '--effort', 'high'],
        ['orchestration', 'worker-show'],
        ['orchestration', 'worker-read'],
        ['orchestration', 'send', '--subject', 'x', '--body', 'y', '--type', 'dispatch'],
      ]) expect(broker.dispatch(args).code).not.toBe(0);
    } finally {
      if (old === undefined) delete process.env.OPENSHELL_BRIDGE_DELEGATION_HOME;
      else process.env.OPENSHELL_BRIDGE_DELEGATION_HOME = old;
      fs.rmSync(home, { recursive: true, force: true });
    }
  });

  test('counts failed launch attempts toward the worker limit', () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'orca-delegation-test-'));
    const bin = path.join(home, 'bin');
    fs.mkdirSync(bin);
    fs.writeFileSync(path.join(bin, 'orca'), '#!/bin/sh\nexit 1\n', { mode: 0o755 });
    const oldHome = process.env.OPENSHELL_BRIDGE_DELEGATION_HOME;
    const oldPath = process.env.PATH;
    process.env.OPENSHELL_BRIDGE_DELEGATION_HOME = home;
    process.env.PATH = `${bin}:${oldPath}`;
    try {
      writeGrant({ terminal: 'terminal-1', workspace: 'id:repo::/workspace', agents: ['codex'], maxWorkers: 1, depth: 0, maxDepth: 1 });
      const broker = new DelegationBroker('sandbox', 'terminal-1', 'repo::/workspace', '/workspace');
      expect(broker.dispatch(['orchestration', 'worker-start', '--spec', 'Task', '--worktree', 'current']).code).toBe(1);
      expect(broker.dispatch(['orchestration', 'worker-start', '--spec', 'Task', '--worktree', 'current']).code).toBe(77);
    } finally {
      if (oldHome === undefined) delete process.env.OPENSHELL_BRIDGE_DELEGATION_HOME;
      else process.env.OPENSHELL_BRIDGE_DELEGATION_HOME = oldHome;
      process.env.PATH = oldPath;
      fs.rmSync(home, { recursive: true, force: true });
    }
  });
});
