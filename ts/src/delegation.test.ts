import { describe, expect, test } from 'bun:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import {
  claimPendingDelegationScope,
  cleanupWorkerScope,
  DelegationBroker,
  readGrant,
  readWorkerScope,
  recordLaunch,
  writeGrant,
} from './delegation.js';
import {
  getStagedUploadPaths,
  resolveSubagentCombinedPolicy,
  resolveSubagentFileScope,
  stageScopedWorkspace,
} from './sandbox-scope.js';
import { mergeWorkspace, snapshotWorkspace } from './workspace-merge.js';

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
      writeGrant({ terminal: 'terminal-1', workspace: 'id:repo::/workspace', agents: ['codex'], maxWorkers: 2, depth: 0, maxDepth: 1, allowNewWorktree: false });
      const broker = new DelegationBroker('sandbox', 'terminal-1', 'repo::/workspace', '/workspace');
      for (const args of [
        ['agent', 'launch', '--agent', 'codex'],
        ['orchestration', 'worker-start', '--spec', 'Task', '--worktree', 'new-top-level'],
        ['orchestration', 'worker-start', '--spec', 'Task', '--worktree', 'new-child'],
        ['orchestration', 'worker-start', '--spec', 'Task', '--name', 'foo'],
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

  test('stages only allowed read/write repository subsets and filters sync-back writes', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'orca-scope-stage-test-'));
    const repo = path.join(root, 'demo-repo');
    const stageRoot = path.join(root, 'stage');
    const dlRoot = path.join(root, 'download');
    try {
      fs.mkdirSync(path.join(repo, 'allowed'), { recursive: true });
      fs.mkdirSync(path.join(repo, 'docs'), { recursive: true });
      fs.mkdirSync(path.join(repo, 'secret'), { recursive: true });
      fs.mkdirSync(path.join(repo, '.git'), { recursive: true });
      fs.writeFileSync(path.join(repo, 'allowed', 'code.ts'), 'export const x = 1;\n');
      fs.writeFileSync(path.join(repo, 'docs', 'spec.md'), '# Spec\n');
      fs.writeFileSync(path.join(repo, 'secret', 'keys.txt'), 'SUPER_SECRET\n');
      fs.writeFileSync(path.join(repo, '.git', 'HEAD'), 'ref: refs/heads/main\n');

      // 1. Subagent gets read access to docs/ and read+write access to allowed/
      const scope = resolveSubagentFileScope(repo, '["docs"]', '["allowed"]');
      expect(scope).toEqual({ readPaths: ['allowed', 'docs'], writePaths: ['allowed'] });

      const stagedPaths = getStagedUploadPaths(scope)!;
      const stagedDir = stageScopedWorkspace(repo, 'demo-repo', stageRoot, stagedPaths);
      expect(fs.existsSync(path.join(stagedDir, 'allowed', 'code.ts'))).toBe(true);
      expect(fs.existsSync(path.join(stagedDir, 'docs', 'spec.md'))).toBe(true);
      expect(fs.existsSync(path.join(stagedDir, 'secret', 'keys.txt'))).toBe(false);
      expect(fs.existsSync(path.join(stagedDir, '.git'))).toBe(false);

      // 2. Simulate edits inside sandbox to both allowed/ and docs/
      const baseline = snapshotWorkspace(repo);
      fs.cpSync(stagedDir, dlRoot, { recursive: true });
      fs.writeFileSync(path.join(dlRoot, 'allowed', 'code.ts'), 'export const x = 2;\n');
      fs.writeFileSync(path.join(dlRoot, 'docs', 'spec.md'), '# Tampered\n');

      const merged = mergeWorkspace(repo, dlRoot, baseline, scope!.writePaths);
      expect(merged.applied).toBe(1);
      expect(fs.readFileSync(path.join(repo, 'allowed', 'code.ts'), 'utf8')).toBe('export const x = 2;\n');
      expect(fs.readFileSync(path.join(repo, 'docs', 'spec.md'), 'utf8')).toBe('# Spec\n');
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  test('validates worker-start file policies, promotes pending scopes, and enforces monotonic attenuation', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'orca-delegation-scope-test-'));
    const home = path.join(root, 'delegation-home');
    const repo = path.join(root, 'repo');
    const bin = path.join(root, 'bin');
    const oldHome = process.env.OPENSHELL_BRIDGE_DELEGATION_HOME;
    const oldPath = process.env.PATH;
    process.env.OPENSHELL_BRIDGE_DELEGATION_HOME = home;
    process.env.PATH = `${bin}:${oldPath}`;

    try {
      fs.mkdirSync(path.join(repo, 'allowed'), { recursive: true });
      fs.mkdirSync(path.join(repo, 'docs'), { recursive: true });
      fs.mkdirSync(path.join(repo, 'secret'), { recursive: true });
      fs.mkdirSync(path.join(repo, '.git'), { recursive: true });
      fs.writeFileSync(path.join(repo, 'allowed', 'a.txt'), 'a');
      fs.writeFileSync(path.join(repo, 'docs', 'd.md'), 'd');
      fs.writeFileSync(path.join(repo, 'secret', 's.txt'), 's');
      fs.symlinkSync(path.join(repo, 'secret'), path.join(repo, 'secret-link'));
      fs.mkdirSync(bin, { recursive: true });
      fs.writeFileSync(path.join(bin, 'sleep'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
      fs.writeFileSync(path.join(bin, 'openshell'), '#!/bin/sh\necho \'{"sandboxes":[]}\'\n', { mode: 0o755 });
      fs.writeFileSync(
        path.join(bin, 'orca'),
        '#!/bin/sh\nexit 1\n',
        { mode: 0o755 }
      );

      // Coordinator with bounded fileScope (can only reach allowed/ and docs/)
      writeGrant({
        terminal: 'coord-1',
        workspace: `id:repo::${repo}`,
        agents: ['claude'],
        maxWorkers: 5,
        depth: 0,
        maxDepth: 2,
        fileScope: { readPaths: ['allowed', 'docs'], writePaths: ['allowed'] },
      });
      const broker = new DelegationBroker('sb-coord', 'coord-1', `repo::${repo}`, repo);

      // Rejects traversal, .git, symlink escape, and paths outside coordinator grant
      expect(broker.dispatch(['orchestration', 'worker-start', '--spec', 'x', '--read-paths', '["../etc"]']).code).toBe(77);
      expect(broker.dispatch(['orchestration', 'worker-start', '--spec', 'x', '--read-paths', '[".git"]']).code).toBe(77);
      expect(broker.dispatch(['orchestration', 'worker-start', '--spec', 'x', '--read-paths', '["secret-link/s.txt"]']).code).toBe(77);
      expect(broker.dispatch(['orchestration', 'worker-start', '--spec', 'x', '--read-paths', '["secret"]']).code).toBe(77);
      expect(broker.dispatch(['orchestration', 'worker-start', '--spec', 'x', '--write-paths', '["docs"]']).code).toBe(77);

      // Valid narrowed scope (writePaths defaults to [] when only --read-paths is given)
      const res = broker.dispatch(['orchestration', 'worker-start', '--spec', 'Read docs', '--agent', 'claude', '--read-paths', '["docs"]']);
      expect(res.code).toBe(1); // mock orca orchestration worker-start exited 1, which cleans up pending scope
      expect(readWorkerScope('structured-agent-session-worker-1')).toBeNull();

      // Verify promotion + clean rollback when OpenShell gateway lacks verified distinct sandbox
      fs.writeFileSync(
        path.join(bin, 'orca'),
        '#!/bin/sh\nif [ "$1" = "orchestration" ] && [ "$2" = "worker-start" ]; then echo \'{"ok":true,"result":{"dispatchId":"d-1","terminal":"structured-agent-session-worker-2"}}\'; exit 0; fi\nexit 0\n',
        { mode: 0o755 }
      );
      const res2 = broker.dispatch(['orchestration', 'worker-start', '--spec', 'Read allowed', '--agent', 'claude', '--read-paths', '["docs"]', '--write-paths', '["allowed"]']);
      expect(res2.code).toBe(1);
      expect(res2.stderr).toContain('lacks verified, distinct OpenShell sandbox');
      expect(readWorkerScope('structured-agent-session-worker-2')).toBeNull();

      // Verify full success path preserves promoted workerScope + attenuated child grant.fileScope
      recordLaunch('structured-agent-session-worker-2', `repo::${repo}`, 'sb-worker-2');
      fs.writeFileSync(
        path.join(bin, 'orca'),
        '#!/bin/sh\nif [ "$1" = "orchestration" ] && [ "$2" = "worker-start" ]; then\n  for f in "$OPENSHELL_BRIDGE_DELEGATION_HOME"/launches/*.json; do [ -f "$f" ] && sed \'s/"at":[ ]*[0-9]*/"at": 9999999999999/\' "$f" > "$f.tmp" && mv "$f.tmp" "$f"; done\n  echo \'{"ok":true,"result":{"dispatchId":"d-1","terminal":"structured-agent-session-worker-2"}}\'\n  exit 0\nfi\nexit 0\n',
        { mode: 0o755 }
      );
      fs.writeFileSync(
        path.join(bin, 'openshell'),
        '#!/bin/sh\necho \'{"sandboxes":[{"name":"sb-coord","id":"id-coord","phase":"Ready"},{"name":"sb-worker-2","id":"id-worker-2","phase":"Ready"}]}\'\n',
        { mode: 0o755 }
      );
      const res3 = broker.dispatch(['orchestration', 'worker-start', '--spec', 'Read allowed', '--agent', 'claude', '--read-paths', '["docs"]', '--write-paths', '["allowed"]']);
      expect(res3.code).toBe(0);
      expect(readWorkerScope('structured-agent-session-worker-2')?.fileScope).toEqual({
        readPaths: ['allowed', 'docs'],
        writePaths: ['allowed'],
      });
      expect(readGrant('structured-agent-session-worker-2', `repo::${repo}`)?.fileScope).toEqual({
        readPaths: ['allowed', 'docs'],
        writePaths: ['allowed'],
      });

      // Direct read-only default check
      expect(resolveSubagentFileScope(repo, '["docs"]', null)).toEqual({ readPaths: ['docs'], writePaths: [] });
      expect(resolveSubagentFileScope(repo, null, '["allowed"]')).toEqual({ readPaths: ['allowed'], writePaths: ['allowed'] });
    } finally {
      if (oldHome === undefined) delete process.env.OPENSHELL_BRIDGE_DELEGATION_HOME;
      else process.env.OPENSHELL_BRIDGE_DELEGATION_HOME = oldHome;
      process.env.PATH = oldPath;
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  test('validates LLM-authored OpenShell policies and enforces network security + monotonic attenuation', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'orca-openshell-llm-pol-'));
    const repo = path.join(root, 'repo');
    try {
      fs.mkdirSync(path.join(repo, 'docs'), { recursive: true });
      fs.writeFileSync(path.join(repo, 'docs', 'spec.md'), '# Spec\n');

      // 1. Valid shorthand + YAML policy
      const combinedJson = resolveSubagentCombinedPolicy({
        projectRoot: repo,
        readRaw: null,
        writeRaw: null,
        openshellPolicyRaw: JSON.stringify({
          readPaths: ['docs'],
          endpoints: [{ host: 'httpbin.org', port: 443, method: 'GET', path: '/get', binaries: ['/usr/bin/curl'] }],
        }),
      });
      expect(combinedJson.fileScope).toEqual({ readPaths: ['docs'], writePaths: [] });
      expect(combinedJson.openshellPolicy?.landlock?.compatibility).toBe('hard_requirement');
      const netVals = Object.values(combinedJson.openshellPolicy?.network_policies || {});
      expect(netVals.length).toBe(1);
      expect(netVals[0]!.endpoints[0]).toEqual({
        host: 'httpbin.org',
        port: 443,
        protocol: 'rest',
        enforcement: 'enforce',
        rules: [{ allow: { method: 'GET', path: '/get' } }],
      });

      const yamlText = [
        'version: 1',
        'readPaths:',
        '  - docs',
        'network_policies:',
        '  gh_api:',
        '    name: gh_api',
        '    endpoints:',
        '      - host: api.github.com',
        '        port: 443',
        '        protocol: rest',
        '        enforcement: enforce',
        '        access: read-only',
      ].join('\n');
      const combinedYaml = resolveSubagentCombinedPolicy({
        projectRoot: repo,
        readRaw: null,
        writeRaw: null,
        openshellPolicyRaw: yamlText,
      });
      expect(combinedYaml.fileScope).toEqual({ readPaths: ['docs'], writePaths: [] });
      expect(combinedYaml.openshellPolicy?.network_policies?.gh_api?.endpoints[0]?.host).toBe('api.github.com');

      // 2. Rejects dangerous overrides
      for (const bad of [
        { landlock: { compatibility: 'best_effort' }, endpoints: [{ host: 'httpbin.org' }] },
        { network_middlewares: { outbound_token_redaction: null }, endpoints: [{ host: 'httpbin.org' }] },
        { process: { run_as_user: 'root' }, endpoints: [{ host: 'httpbin.org' }] },
        { filesystem_policy: { include_workdir: true } },
        { filesystem_policy: { read_write: ['/sandbox/secret'] } },
        { filesystem_policy: { read_only: ['/Users/cedric/.ssh'] } },
        { endpoints: [{ host: 'api.anthropic.com' }] },
        { endpoints: [{ host: '169.254.169.254' }] },
        { endpoints: [{ host: '127.0.0.1' }] },
        { endpoints: [{ host: 'localhost' }] },
        { endpoints: [{ host: 'httpbin.org', enforcement: 'audit' }] },
        { endpoints: [{ host: 'httpbin.org', request_body_credential_rewrite: true }] },
      ]) {
        expect(() =>
          resolveSubagentCombinedPolicy({
            projectRoot: repo,
            readRaw: null,
            writeRaw: null,
            openshellPolicyRaw: JSON.stringify(bad),
          })
        ).toThrow();
      }

      // 3. Rejects host outside allowedEgressHosts or parentOpenShellPolicy
      expect(() =>
        resolveSubagentCombinedPolicy({
          projectRoot: repo,
          readRaw: null,
          writeRaw: null,
          openshellPolicyRaw: JSON.stringify({ endpoints: [{ host: 'example.com' }] }),
          allowedEgressHosts: ['httpbin.org'],
        })
      ).toThrow(/allowedEgressHosts/);

      expect(() =>
        resolveSubagentCombinedPolicy({
          projectRoot: repo,
          readRaw: null,
          writeRaw: null,
          openshellPolicyRaw: JSON.stringify({ endpoints: [{ host: 'example.com' }] }),
          parentOpenShellPolicy: combinedJson.openshellPolicy,
        })
      ).toThrow(/exceeds parent worker/);

      // 4. Grandchild inherits parentOpenShellPolicy if none specified
      const inherited = resolveSubagentCombinedPolicy({
        projectRoot: repo,
        readRaw: '["docs"]',
        writeRaw: null,
        openshellPolicyRaw: null,
        parentOpenShellPolicy: combinedJson.openshellPolicy,
      });
      expect(inherited.openshellPolicy).toEqual(combinedJson.openshellPolicy);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  test('creates new-child worktree, installs temporary policy before sandbox launch, and removes it on teardown or rollback', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'orca-worktree-policy-test-'));
    const home = path.join(root, 'delegation-home');
    const repo = path.join(root, 'repo');
    const childWt = path.join(root, 'repo-child');
    const bin = path.join(root, 'bin');
    const oldHome = process.env.OPENSHELL_BRIDGE_DELEGATION_HOME;
    const oldPath = process.env.PATH;
    process.env.OPENSHELL_BRIDGE_DELEGATION_HOME = home;
    process.env.PATH = `${bin}:${oldPath}`;

    try {
      fs.mkdirSync(path.join(repo, 'docs'), { recursive: true });
      fs.writeFileSync(path.join(repo, 'docs', 'guide.md'), '# Guide\n');
      execFileSync('git', ['init', '-q'], { cwd: repo });
      execFileSync('git', ['config', 'user.email', 'test@example.com'], { cwd: repo });
      execFileSync('git', ['config', 'user.name', 'Test'], { cwd: repo });
      execFileSync('git', ['add', '.'], { cwd: repo });
      execFileSync('git', ['commit', '-q', '-m', 'init'], { cwd: repo });

      // Mock orca creates child git worktree + tracks launches + removes on rm
      const rmLog = path.join(root, 'rm.log');
      const launchSawTempPolicy = path.join(root, 'saw-policy.txt');
      fs.mkdirSync(bin, { recursive: true });
      fs.writeFileSync(path.join(bin, 'sleep'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
      fs.writeFileSync(
        path.join(bin, 'openshell'),
        '#!/bin/sh\necho \'{"sandboxes":[{"name":"sb-coord","id":"id-coord","phase":"Ready"},{"name":"sb-child-1","id":"id-child-1","phase":"Ready"}]}\'\n',
        { mode: 0o755 }
      );
      fs.writeFileSync(
        path.join(bin, 'orca'),
        `#!/bin/sh
if [ "$1" = "worktree" ] && [ "$2" = "create" ]; then
  git -C "${repo}" worktree add -q -b child-branch "${childWt}"
  echo '{"ok":true,"result":{"worktree":{"id":"repo::${childWt}","path":"${childWt}"}}}'
  exit 0
fi
if [ "$1" = "worktree" ] && [ "$2" = "rm" ]; then
  echo "$@" >> "${rmLog}"
  rm -rf "${childWt}"
  exit 0
fi
if [ "$1" = "orchestration" ] && [ "$2" = "worker-start" ]; then
  if ls "${childWt}/.agents/policies"/.orca-openshell-temp-*.json >/dev/null 2>&1; then
    echo "PRESENT" > "${launchSawTempPolicy}"
  fi
  for f in "$OPENSHELL_BRIDGE_DELEGATION_HOME"/launches/*.json; do
    [ -f "$f" ] && sed 's/"at":[ ]*[0-9]*/"at": 9999999999999/' "$f" > "$f.tmp" && mv "$f.tmp" "$f"
  done
  echo '{"ok":true,"result":{"dispatchId":"d-child-1","terminal":"structured-agent-session-child-1"}}'
  exit 0
fi
exit 0
`,
        { mode: 0o755 }
      );

      writeGrant({
        terminal: 'coord-wt',
        workspace: `id:repo::${repo}`,
        agents: ['claude'],
        maxWorkers: 4,
        depth: 0,
        maxDepth: 2,
      });
      const broker = new DelegationBroker('sb-coord', 'coord-wt', `repo::${repo}`, repo);
      recordLaunch('structured-agent-session-child-1', `repo::${childWt}`, 'sb-child-1');

      const res = broker.dispatch([
        'orchestration',
        'worker-start',
        '--agent',
        'claude',
        '--worktree',
        'new-child',
        '--name',
        'httpbin-worker',
        '--spec',
        'Fetch httpbin get',
        '--read-paths',
        '["docs"]',
        '--openshell-policy',
        JSON.stringify({
          endpoints: [{ host: 'httpbin.org', port: 443, method: 'GET', path: '/get', binaries: ['/usr/bin/curl'] }],
        }),
      ]);
      expect(res.code).toBe(0);

      // Temporary policy existed in child worktree BEFORE agent launch!
      expect(fs.readFileSync(launchSawTempPolicy, 'utf8').trim()).toBe('PRESENT');

      const workerScope = readWorkerScope('structured-agent-session-child-1', `repo::${childWt}`);
      expect(workerScope).not.toBeNull();
      expect(workerScope?.tempPolicyFilePath).toBeTruthy();
      expect(fs.existsSync(workerScope!.tempPolicyFilePath!)).toBe(true);

      // Git status inside child worktree remains clean because .orca-openshell-temp-*.json is excluded
      const gitStatus = execFileSync('git', ['status', '--porcelain'], { cwd: childWt, encoding: 'utf8' });
      expect(gitStatus.trim()).toBe('');

      // Teardown cleanup removes temporary policy file and empty created .agents dirs
      cleanupWorkerScope('structured-agent-session-child-1');
      expect(fs.existsSync(workerScope!.tempPolicyFilePath!)).toBe(false);
      expect(fs.existsSync(path.join(childWt, '.agents'))).toBe(false);
      expect(readWorkerScope('structured-agent-session-child-1')).toBeNull();

      // Verify rollback removes temp policy AND child worktree if sandbox fails verification
      fs.writeFileSync(
        path.join(bin, 'openshell'),
        '#!/bin/sh\necho \'{"sandboxes":[{"name":"sb-coord","id":"id-coord","phase":"Ready"}]}\'\n',
        { mode: 0o755 }
      );
      const failRes = broker.dispatch([
        'orchestration',
        'worker-start',
        '--agent',
        'claude',
        '--worktree',
        'new-child',
        '--name',
        'fail-worker',
        '--spec',
        'Fail check',
        '--openshell-policy',
        JSON.stringify({ endpoints: [{ host: 'httpbin.org', access: 'read-only' }] }),
      ]);
      expect(failRes.code).toBe(1);
      expect(fs.existsSync(rmLog)).toBe(true);
      expect(fs.readFileSync(rmLog, 'utf8')).toContain('worktree rm');
      expect(fs.existsSync(childWt)).toBe(false);
    } finally {
      if (oldHome === undefined) delete process.env.OPENSHELL_BRIDGE_DELEGATION_HOME;
      else process.env.OPENSHELL_BRIDGE_DELEGATION_HOME = oldHome;
      process.env.PATH = oldPath;
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  test('supports ambient ORCA_AGENT_SESSION_ID coordinators and structworker runtime claiming', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'orca-ambient-claim-test-'));
    const home = path.join(root, 'delegation-home');
    const repo = path.join(root, 'repo');
    const bin = path.join(root, 'bin');
    const argsLog = path.join(root, 'orca-args.log');
    const oldHome = process.env.OPENSHELL_BRIDGE_DELEGATION_HOME;
    const oldPath = process.env.PATH;
    const oldSid = process.env.ORCA_AGENT_SESSION_ID;
    process.env.OPENSHELL_BRIDGE_DELEGATION_HOME = home;
    process.env.PATH = `${bin}:${oldPath}`;
    process.env.ORCA_AGENT_SESSION_ID = 'coord-sess-123';

    try {
      fs.mkdirSync(path.join(repo, 'docs'), { recursive: true });
      fs.writeFileSync(path.join(repo, 'docs', 'a.md'), 'hi');
      fs.mkdirSync(bin, { recursive: true });
      fs.writeFileSync(path.join(bin, 'sleep'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
      fs.writeFileSync(
        path.join(bin, 'openshell'),
        '#!/bin/sh\necho \'{"sandboxes":[{"name":"sb-coord","id":"id-coord","phase":"Ready"},{"name":"sb-child","id":"id-child","phase":"Ready"}]}\'\n',
        { mode: 0o755 }
      );
      fs.writeFileSync(
        path.join(bin, 'orca'),
        `#!/bin/sh\necho "$@|$ORCA_AGENT_SESSION_ID" >> "${argsLog}"\nif [ "$1" = "orchestration" ] && [ "$2" = "worker-start" ]; then\n  echo '{"ok":true,"result":{"dispatchId":"d-struct-1","terminal":"structworker_abc"}}'\n  exit 0\nfi\nexit 0\n`,
        { mode: 0o755 }
      );

      writeGrant({
        terminal: 'structured-agent-session-coord-sess-123',
        workspace: `id:repo::${repo}`,
        agents: ['claude'],
        maxWorkers: 2,
        depth: 0,
        maxDepth: 2,
      });
      const broker = new DelegationBroker('sb-coord', 'structured-agent-session-coord-sess-123', `repo::${repo}`, repo);

      // Ambient coordinator check omits --terminal and keeps ORCA_AGENT_SESSION_ID
      expect(broker.dispatch(['orchestration', 'check']).code).toBe(0);
      const checkLog = fs.readFileSync(argsLog, 'utf8').trim();
      expect(checkLog).not.toContain('--terminal');
      expect(checkLog).toContain('|coord-sess-123');

      // Non-matching broker strips ORCA_AGENT_SESSION_ID and includes --from
      const otherBroker = new DelegationBroker('sb-other', 'term_other', `repo::${repo}`, repo);
      writeGrant({ terminal: 'term_other', workspace: `id:repo::${repo}`, agents: ['claude'], maxWorkers: 2, depth: 0, maxDepth: 2 });
      expect(otherBroker.dispatch(['orchestration', 'check']).code).toBe(0);
      const otherLog = fs.readFileSync(argsLog, 'utf8').trim().split('\n').pop()!;
      expect(otherLog).toContain('--terminal term_other');
      expect(otherLog.endsWith('|')).toBe(true);

      // Direct claimPendingDelegationScope resolves structworker sandbox session ID cleanly
      recordLaunch('structured-agent-session-child-uuid', `repo::${repo}`, 'sb-child');
      // Pre-seed claim inside openshell/mock flow? Here we test claimPendingDelegationScope + workerStart rollback if unclaimed
      const resUnclaimed = broker.dispatch(['orchestration', 'worker-start', '--agent', 'claude', '--worktree', 'current', '--spec', 'hi', '--read-paths', '["docs"]']);
      expect(resUnclaimed.code).toBe(1);
      expect(resUnclaimed.stderr).toContain('lacks verified, distinct OpenShell sandbox');
      const startLog = fs.readFileSync(argsLog, 'utf8');
      expect(startLog).not.toContain('--from structured-agent-session-coord-sess-123');
      // Check claimPendingDelegationScope directly writes scope + grant
      const pendingIdDir = path.join(home, 'pending-scopes');
      fs.mkdirSync(pendingIdDir, { recursive: true });
      const pidFile = path.join(pendingIdDir, 'manual-test.json');
      fs.writeFileSync(pidFile, JSON.stringify({
        id: 'manual-test',
        workspace: `id:repo::${repo}`,
        projectRoot: repo,
        agent: 'claude',
        fileScope: { readPaths: ['docs'], writePaths: [] },
        pendingGrant: { workspace: `id:repo::${repo}`, agents: ['claude'], maxWorkers: 2, depth: 1, maxDepth: 2 },
        at: Date.now(),
      }));
      const claimed = claimPendingDelegationScope('structured-agent-session-child-uuid', `repo::${repo}`, 'claude');
      expect(claimed?.fileScope).toEqual({ readPaths: ['docs'], writePaths: [] });
      expect(readGrant('structured-agent-session-child-uuid', `repo::${repo}`)?.depth).toBe(1);
    } finally {
      if (oldHome === undefined) delete process.env.OPENSHELL_BRIDGE_DELEGATION_HOME;
      else process.env.OPENSHELL_BRIDGE_DELEGATION_HOME = oldHome;
      if (oldSid === undefined) delete process.env.ORCA_AGENT_SESSION_ID;
      else process.env.ORCA_AGENT_SESSION_ID = oldSid;
      process.env.PATH = oldPath;
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});

