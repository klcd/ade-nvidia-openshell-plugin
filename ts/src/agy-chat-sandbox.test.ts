import { describe, expect, test } from 'bun:test';
import {
  detectBlockedEgress,
  getAgySessionDir,
  resolveAgyProjectRoot,
  translateAgyCommandAndCwd,
} from './agy-chat-sandbox.js';

describe('Antigravity Chat Mode OpenShell Sandbox Helpers', () => {
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

  test('getAgySessionDir sanitizes session keys into deterministic /tmp directory', () => {
    const dir = getAgySessionDir('antigravity_b153a235_11ff_438c');
    expect(dir).toContain('/tmp/orca-ag-openshell-');
    expect(dir.endsWith('/antigravity_b153a235_11ff_438c')).toBe(true);
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
});
