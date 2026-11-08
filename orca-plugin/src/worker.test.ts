import { strict as assert } from 'node:assert'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { test } from 'node:test'
import activate, { bridgeCommand } from './worker.ts'

test('rewrites Orca launch command while preserving flags and prompt', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'orca-bridge-test-'))
  try {
    fs.writeFileSync(path.join(dir, 'codex-box'), '')
    fs.writeFileSync(path.join(dir, 'agy-box'), '')
    assert.equal(bridgeCommand('codex', 'codex --model test "prompt here"', dir),
      `'${path.join(dir, 'codex-box')}' --model test "prompt here"`)
    assert.equal(bridgeCommand('antigravity', "agy '--dangerously-skip-permissions'", dir),
      `'${path.join(dir, 'agy-box')}' '--dangerously-skip-permissions'`)
    assert.equal(bridgeCommand('agy', "agy --prompt 'hi'", dir),
      `'${path.join(dir, 'agy-box')}' --prompt 'hi'`)
    assert.equal(bridgeCommand('opencode', 'opencode', dir), null)
    assert.throws(() => bridgeCommand('codex', 'sh -c codex', dir), /Unexpected/)
    assert.throws(() => bridgeCommand('claude', 'claude', dir), /missing/)
  } finally {
    fs.rmSync(dir, { recursive: true, force: true })
  }
})

test('hook denies a supported agent when wrapper is absent', () => {
  let handler: ((event: any, next: (event?: any) => any) => any) | undefined
  activate({ hooks: { on: (_name: string, fn: typeof handler) => { handler = fn } }, log() {} } as any)
  assert.ok(handler)
  const before = process.env.ORCA_OPENSHELL_BRIDGE_BIN_DIR
  process.env.ORCA_OPENSHELL_BRIDGE_BIN_DIR = '/definitely-not-installed-orca-bridge'
  try {
    const result = handler({ agent: 'codex', workspaceId: 'ws', command: 'codex', env: {} }, x => x)
    assert.match(result.deny, /missing/)
  } finally {
    if (before === undefined) delete process.env.ORCA_OPENSHELL_BRIDGE_BIN_DIR
    else process.env.ORCA_OPENSHELL_BRIDGE_BIN_DIR = before
  }
})

test('hook forwards only nonreserved environment keys accepted by Orca', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'orca-hook-test-'))
  const policies = path.join(dir, 'policies')
  fs.mkdirSync(policies)
  fs.writeFileSync(path.join(dir, 'codex-box'), '')
  fs.writeFileSync(path.join(policies, 'codex.json'), '{}')
  const oldBin = process.env.ORCA_OPENSHELL_BRIDGE_BIN_DIR
  const oldPolicy = process.env.ORCA_OPENSHELL_POLICY_DIR
  process.env.ORCA_OPENSHELL_BRIDGE_BIN_DIR = dir
  process.env.ORCA_OPENSHELL_POLICY_DIR = policies
  try {
    let handler: ((event: any, next: (event?: any) => any) => any) | undefined
    activate({ hooks: { on: (_name: string, fn: typeof handler) => { handler = fn } }, log() {} } as any)
    assert.ok(handler)
    const result = handler({ agent: 'codex', workspaceId: 'ws', terminalId: 'term', command: 'codex --version', env: {
      OPENSHELL_BRIDGE_TERMINAL_ID: 'forged',
      OPENSHELL_BRIDGE_SHIM_PATH: '/tmp/forged',
    } }, x => x)
    assert.equal(result.env.OPENSHELL_BRIDGE_REQUIRED, '1')
    assert.equal(result.env.OPENSHELL_BRIDGE_POLICY_FILE, path.join(policies, 'codex.json'))
    assert.equal(result.env.OPENSHELL_BRIDGE_TERMINAL_ID, 'term')
    assert.equal(result.env.OPENSHELL_BRIDGE_WORKSPACE_ID, 'ws')
    assert.equal(result.env.OPENSHELL_BRIDGE_SHIM_PATH, undefined)
    assert.ok(Object.keys(result.env).every(key => !key.startsWith('ORCA_')))
  } finally {
    if (oldBin === undefined) delete process.env.ORCA_OPENSHELL_BRIDGE_BIN_DIR
    else process.env.ORCA_OPENSHELL_BRIDGE_BIN_DIR = oldBin
    if (oldPolicy === undefined) delete process.env.ORCA_OPENSHELL_POLICY_DIR
    else process.env.ORCA_OPENSHELL_POLICY_DIR = oldPolicy
    fs.rmSync(dir, { recursive: true, force: true })
  }
})
