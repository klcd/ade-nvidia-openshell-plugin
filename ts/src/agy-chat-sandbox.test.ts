import fs from 'fs';
import os from 'os';
import path from 'path';
import { describe, expect, test } from 'bun:test';
import {
  acquireAgyExecLock,
  detectBlockedEgress,
  getAgySessionDir,
  hasActiveAgyExecs,
  readLastAgyActivity,
  resolveAgyProjectRoot,
  touchAgyActivity,
  translateAgyCommandAndCwd,
} from './agy-chat-sandbox.js';
import { getSandboxIdleTimeoutSeconds, unregisterSandboxSession } from './config.js';
import { ensureValidHostTmpDir } from './sandbox.js';

describe('Antigravity Chat Mode OpenShell Sandbox Helpers', () => {
  test('activity timestamps and active-exec locks guard idle hibernation', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agy-hib-test-'));
    try {
      expect(readLastAgyActivity(tmpDir)).toBe(0);
      touchAgyActivity(tmpDir, 1700000000123);
      expect(readLastAgyActivity(tmpDir)).toBe(1700000000123);

      expect(hasActiveAgyExecs(tmpDir)).toBe(false);

      // Lock for current live PID blocks hibernation until released
      const release = acquireAgyExecLock(tmpDir, process.pid);
      expect(hasActiveAgyExecs(tmpDir)).toBe(true);
      release();
      expect(hasActiveAgyExecs(tmpDir)).toBe(false);

      // Stale lock for a non-existent PID is automatically pruned
      acquireAgyExecLock(tmpDir, 99999999);
      expect(hasActiveAgyExecs(tmpDir)).toBe(false);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  test('translateAgyCommandAndCwd maps host workspace paths and subdirectories to container paths', () => {
    const projectRoot = '/Users/cedric/Projects/ade-nvidia-openshell-plugin';
    const containerRoot = '/sandbox/ade-nvidia-openshell-plugin';

    const sub = translateAgyCommandAndCwd(
      'cat /Users/cedric/Projects/ade-nvidia-openshell-plugin/orca-plugin/package.json && whoami',
      '/Users/cedric/Projects/ade-nvidia-openshell-plugin/orca-plugin',
      projectRoot,
      containerRoot
    );
    expect(sub.containerCwd).toBe('/sandbox/ade-nvidia-openshell-plugin/orca-plugin');
    expect(sub.translatedCommand).toBe('cat /sandbox/ade-nvidia-openshell-plugin/orca-plugin/package.json && whoami');
  });

  test('translateAgyCommandAndCwd falls back to containerRoot when hostCwd is Antigravity skills dir', () => {
    const projectRoot = '/Users/cedric/Projects/ade-nvidia-openshell-plugin';
    const containerRoot = '/sandbox/ade-nvidia-openshell-plugin';

    const res = translateAgyCommandAndCwd(
      'whoami',
      '/Users/cedric/Library/Application Support/orca/antigravity-chat/antigravity-cli/skills',
      projectRoot,
      containerRoot
    );
    expect(res.containerCwd).toBe('/sandbox/ade-nvidia-openshell-plugin');
    expect(res.translatedCommand).toBe('whoami');
  });

  test('getAgySessionDir stores session state in ~/.orca/ag and keeps ctl.sock under macOS 104-byte limit', () => {
    const longSessionKey = 'antigravity_311ee386_d918_4962_8130_9d0a9cd251ce_extra_suffix';
    const dir = getAgySessionDir(longSessionKey);
    expect(dir).toContain(path.join('.orca', 'ag'));
    expect(dir).not.toContain('/tmp/');
    expect(path.basename(dir).length).toBeLessThanOrEqual(24);
    expect(path.join(dir, 'ctl.sock').length).toBeLessThan(104);

    const shortDir = getAgySessionDir('ag-ppid-12345');
    expect(shortDir.endsWith(path.join('.orca', 'ag', 'ag-ppid-12345'))).toBe(true);
  });

  test('resolveAgyProjectRoot honours AG_HOST_WORKDIR when set', () => {
    const prev = process.env.AG_HOST_WORKDIR;
    process.env.AG_HOST_WORKDIR = '/Users/cedric/Projects/ade-nvidia-openshell-plugin';
    try {
      const root = resolveAgyProjectRoot(
        '/Users/cedric/Library/Application Support/orca/antigravity-chat/antigravity-cli/skills',
        0
      );
      expect(root).toBe('/Users/cedric/Projects/ade-nvidia-openshell-plugin');
    } finally {
      if (prev === undefined) delete process.env.AG_HOST_WORKDIR;
      else process.env.AG_HOST_WORKDIR = prev;
    }
  });

  test('detectBlockedEgress extracts host, port, method, and path from blocked curl command', () => {
    const blocked = detectBlockedEgress(
      'curl -isS --max-time 5 https://api.github.com/zen',
      7,
      '',
      "curl: (7) Failed to connect to api.github.com port 443 after 3 ms: Couldn't connect to server"
    );
    expect(blocked).toEqual({
      host: 'api.github.com',
      port: 443,
      method: 'GET',
      path: '/zen',
      binary: '*',
      commandLine: 'curl -isS --max-time 5 https://api.github.com/zen',
    });
  });

  test('detectBlockedEgress extracts exact rule_missing from OpenShell L7 HTTP 403 response', () => {
    const stdout = [
      'HTTP/1.1 403 Forbidden',
      'X-OpenShell-Policy: httpbin_org_l7',
      '',
      '{"binary":"/usr/bin/curl","detail":"POST /post not permitted by policy","error":"policy_denied","host":"httpbin.org","layer":"l7","method":"POST","next_steps":[],"path":"/post","policy":"httpbin_org_l7","port":443,"protocol":"rest","rule":"POST /post","rule_missing":{"binary":"/usr/bin/curl","host":"httpbin.org","layer":"l7","method":"POST","path":"/post","port":443,"type":"rest_allow"}}',
    ].join('\r\n');
    const blocked = detectBlockedEgress(
      'curl -isS -X POST https://httpbin.org/post',
      0,
      stdout,
      ''
    );
    expect(blocked).toEqual({
      host: 'httpbin.org',
      port: 443,
      method: 'POST',
      path: '/post',
      binary: '/usr/bin/curl',
      commandLine: 'curl -isS -X POST https://httpbin.org/post',
    });
  });

  test('getSandboxIdleTimeoutSeconds resolves per-tab timeout by sandboxName and agentSessionId', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agy-tab-idle-test-'));
    const modeFile = path.join(tmpDir, 'sandbox-mode.json');
    const prevMode = process.env.ORCA_OPENSHELL_MODE_FILE;
    process.env.ORCA_OPENSHELL_MODE_FILE = modeFile;
    try {
      fs.writeFileSync(
        modeFile,
        JSON.stringify({
          tabIdleTimeouts: {
            'sandbox:ag-tab-1': { seconds: 60 },
            'session:antigravity_tab_1': { seconds: 60 },
            'sandbox:ag-tab-2': { seconds: 0 },
          },
        })
      );

      expect(getSandboxIdleTimeoutSeconds(tmpDir, { sandboxName: 'ag-tab-1' })).toBe(60);
      expect(getSandboxIdleTimeoutSeconds(tmpDir, { sandboxName: 'ag-tab-2' })).toBe(0);
      expect(getSandboxIdleTimeoutSeconds(tmpDir, { sandboxName: 'ag-tab-3' })).toBe(300);

      unregisterSandboxSession('ag-tab-1', tmpDir);
      // After sandbox deletion, session-keyed timeout still applies if recreated in the same tab
      expect(
        getSandboxIdleTimeoutSeconds(tmpDir, {
          sandboxName: 'ag-tab-1-recreated',
          agentSessionId: 'antigravity_tab_1',
        })
      ).toBe(60);
    } finally {
      if (prevMode === undefined) delete process.env.ORCA_OPENSHELL_MODE_FILE;
      else process.env.ORCA_OPENSHELL_MODE_FILE = prevMode;
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  test('ensureValidHostTmpDir resets ephemeral oacp and missing TMPDIR values to /tmp', () => {
    const prevTmp = process.env.TMPDIR;
    try {
      process.env.TMPDIR = '/tmp/oacp-501/045d92ce/run-ephemeral';
      ensureValidHostTmpDir();
      expect(process.env.TMPDIR).toBe('/tmp');

      process.env.TMPDIR = '/tmp/nonexistent-orca-test-dir-999999';
      ensureValidHostTmpDir();
      expect(process.env.TMPDIR).toBe('/tmp');
    } finally {
      if (prevTmp === undefined) delete process.env.TMPDIR;
      else process.env.TMPDIR = prevTmp;
    }
  });
});
