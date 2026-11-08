import { describe, expect, it } from 'bun:test';
import { generateSandboxName } from './config.js';
import { CodexAdapter } from './agents/codex.js';
import { ClaudeAdapter } from './agents/claude.js';
import { AntigravityAdapter } from './agents/antigravity.js';
import { mergeTwoPolicies } from './policy.js';
import { createJsonRpcPathTransform } from './protocols/jsonrpc.js';
import { buildStreamingSshArgs } from './runner.js';

describe('Orca OpenShell launch safety', () => {
  it('uses a distinct, valid sandbox name for each process launch', () => {
    const names = Array.from({ length: 100 }, () => generateSandboxName('cx', 'workspace', 12345));
    expect(new Set(names).size).toBe(names.length);
    for (const name of names) expect(name.length).toBeLessThanOrEqual(19);
  });

  it('disables standalone host bypasses for Orca launches', () => {
    const before = process.env.OPENSHELL_BRIDGE_REQUIRED;
    process.env.OPENSHELL_BRIDGE_REQUIRED = '1';
    try {
      expect(new CodexAdapter().shouldBypassSandbox(['--version'], '/tmp')).toBe(false);
      expect(new ClaudeAdapter().shouldBypassSandbox(['--help'], '/tmp')).toBe(false);
      expect(new AntigravityAdapter().shouldBypassSandbox(['--version'], '/tmp')).toBe(false);
    } finally {
      if (before === undefined) delete process.env.OPENSHELL_BRIDGE_REQUIRED;
      else process.env.OPENSHELL_BRIDGE_REQUIRED = before;
    }
  });

  it('allows background /tmp and model discovery probes in standalone mode but enforces sandbox for ORCA_STRUCTURED_SESSION', () => {
    const beforeReq = process.env.OPENSHELL_BRIDGE_REQUIRED;
    const beforeStruct = process.env.ORCA_STRUCTURED_SESSION;
    delete process.env.OPENSHELL_BRIDGE_REQUIRED;
    delete process.env.ORCA_STRUCTURED_SESSION;
    try {
      expect(new CodexAdapter().shouldBypassSandbox(['probe'], '/tmp')).toBe(true);
      expect(new ClaudeAdapter().shouldBypassSandbox(['probe'], '/tmp')).toBe(true);
      expect(new ClaudeAdapter().shouldBypassSandbox(['-p', '--settings', '{"disableAllHooks":true}'], '/workspace')).toBe(true);
      expect(new AntigravityAdapter().shouldBypassSandbox(['probe'], '/private/tmp')).toBe(true);

      process.env.ORCA_STRUCTURED_SESSION = '1';
      expect(new ClaudeAdapter().shouldBypassSandbox(['--output-format', 'stream-json'], '/workspace')).toBe(false);
      expect(new CodexAdapter().shouldBypassSandbox(['app-server'], '/workspace')).toBe(false);
    } finally {
      if (beforeReq !== undefined) process.env.OPENSHELL_BRIDGE_REQUIRED = beforeReq;
      else delete process.env.OPENSHELL_BRIDGE_REQUIRED;
      if (beforeStruct !== undefined) process.env.ORCA_STRUCTURED_SESSION = beforeStruct;
      else delete process.env.ORCA_STRUCTURED_SESSION;
    }
  });

  it('uses --no-tty and rewrites host --add-dir / --plugin-dir flags for Claude stream-json Chat Mode', () => {
    const adapter = new ClaudeAdapter();
    const args = adapter.buildExecArgs(
      'cc-safe-o-123',
      'safe-orca-setup',
      ['--output-format', 'stream-json', '--input-format', 'stream-json', '--add-dir', '/Users/cedric/Library/Application Support/orca/attachments', '--plugin-dir=/Users/cedric/Library/Application Support/orca/visuals'],
      {}
    );
    expect(args).toContain('--no-tty');
    expect(args).not.toContain('--tty');
    const addDirIdx = args.indexOf('--add-dir');
    expect(addDirIdx).toBeGreaterThan(-1);
    expect(args[addDirIdx + 1]).toStartWith('/sandbox/.claude/orca-host-dirs/');
    expect(args.some(a => a.startsWith('--plugin-dir=/sandbox/.claude/orca-host-dirs/'))).toBe(true);
  });

  it('invokes onTurnComplete before flushing result frames in containerToHost stream transform', async () => {
    let synced = 0;
    const transform = createJsonRpcPathTransform(
      '/Users/cedric/Projects/safe-orca-setup',
      '/sandbox/safe-orca-setup',
      'containerToHost',
      async () => {
        synced += 1;
      }
    );
    const chunks: string[] = [];
    transform.on('data', chunk => chunks.push(chunk.toString('utf8')));
    transform.write('{"type":"assistant","cwd":"/sandbox/safe-orca-setup"}\n');
    transform.write('{"type":"result","subtype":"success","cwd":"/sandbox/safe-orca-setup"}\n');
    await new Promise<void>(resolve => transform.end(resolve));
    expect(synced).toBe(1);
    expect(chunks.join('')).toContain('"/Users/cedric/Projects/safe-orca-setup"');
  });

  it('builds SSH streaming args for persistent JSON-RPC / stream-json sessions', () => {
    const sshArgs = buildStreamingSshArgs(
      [
        'sandbox', 'exec',
        '--name', 'cc-safe-o-1234',
        '--workdir', '/sandbox/safe-orca-setup',
        '--no-tty',
        '--env', 'ORCA_STRUCTURED_SESSION=1',
        '--',
        'claude', '--output-format', 'stream-json', '--input-format', 'stream-json',
      ],
      'Host openshell-cc-safe-o-1234.default\n    User sandbox\n',
      '/tmp/ssh_config'
    );
    expect(sshArgs.slice(0, 4)).toEqual(['-T', '-F', '/tmp/ssh_config', 'openshell-cc-safe-o-1234.default']);
    expect(sshArgs[4]).toContain('/sandbox/safe-orca-setup');
    expect(sshArgs[4]).toContain('ORCA_STRUCTURED_SESSION=1');
    expect(sshArgs[4]).toContain('--output-format');
    expect(sshArgs[4]).toContain('stream-json');
  });

  it('merges project policies onto explicit Orca policies without dropping paths', () => {
    const merged = mergeTwoPolicies(
      { version: 1, filesystem_policy: { include_workdir: true, read_only: ['/bin'], read_write: ['/tmp'] } },
      { version: 1, filesystem_policy: { include_workdir: true, read_only: ['/opt/custom'], read_write: ['/var/tmp'] } }
    );
    expect(merged.filesystem_policy?.read_only).toEqual(['/bin', '/opt/custom']);
    expect(merged.filesystem_policy?.read_write).toEqual(['/tmp', '/var/tmp']);
  });
});
