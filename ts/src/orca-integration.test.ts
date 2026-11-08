import { describe, expect, it } from 'bun:test';
import { generateSandboxName } from './config.js';
import { CodexAdapter } from './agents/codex.js';
import { ClaudeAdapter } from './agents/claude.js';
import { AntigravityAdapter } from './agents/antigravity.js';
import { mergeTwoPolicies } from './policy.js';

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

  it('allows background /tmp probes in standalone mode across all adapters', () => {
    const before = process.env.OPENSHELL_BRIDGE_REQUIRED;
    delete process.env.OPENSHELL_BRIDGE_REQUIRED;
    try {
      expect(new CodexAdapter().shouldBypassSandbox(['probe'], '/tmp')).toBe(true);
      expect(new ClaudeAdapter().shouldBypassSandbox(['probe'], '/tmp')).toBe(true);
      expect(new AntigravityAdapter().shouldBypassSandbox(['probe'], '/private/tmp')).toBe(true);
    } finally {
      if (before !== undefined) process.env.OPENSHELL_BRIDGE_REQUIRED = before;
    }
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
