import { strict as assert } from 'node:assert'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { test } from 'node:test'
import activate, { bridgeCommand, formatCliPolicySummary } from './worker.ts'
import { addL7Policy, buildPolicyReport, evaluateCommandPolicy, parsePermissionYaml } from './policy-inspector.ts'

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

test('parses permission policies coupled to CLI commands and evaluates command compatibility', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'orca-policy-inspector-test-'))
  try {
    const homeDir = path.join(dir, 'home')
    const wsDir = path.join(dir, 'workspace')
    const permDir = path.join(homeDir, '.agents', 'permissions')
    const wsPermDir = path.join(wsDir, '.agents', 'permissions')
    fs.mkdirSync(permDir, { recursive: true })
    fs.mkdirSync(wsPermDir, { recursive: true })

    fs.writeFileSync(
      path.join(permDir, 'security-baseline.yml'),
      [
        'name: security-baseline',
        'description: Baseline security rules',
        'allow:',
        '  - "Bash(pwd)"',
        '  - "Bash(git status:*)"',
        'deny:',
        '  - "Bash(sudo)"',
        '  - "Bash(sudo:*)"',
      ].join('\n')
    )
    fs.writeFileSync(
      path.join(wsPermDir, 'project.yml'),
      [
        'name: project',
        'description: Project workflow commands',
        'allow:',
        '  - "Bash(bun test)"',
        '  - "Bash(bun test:*)"',
      ].join('\n')
    )

    const group = parsePermissionYaml(
      fs.readFileSync(path.join(permDir, 'security-baseline.yml'), 'utf8'),
      'security-baseline.yml',
      'global'
    )
    assert.equal(group.allowCount, 2)
    assert.equal(group.denyCount, 2)
    assert.equal(group.rules[1].cliCommand, 'git status [args...]')

    const report = buildPolicyReport({ workspacePath: wsDir, agent: 'codex', homeDir })
    assert.equal(report.permissionGroups.length, 2)
    assert.equal(report.workspaces.length, 1)
    assert.equal(report.selectedWorkspace.path, wsDir)
    assert.equal(report.currentAgent, 'codex')
    assert.equal(report.agents.length, 1)
    assert.equal(report.agents[0].agent, 'codex')

    const allowEval = evaluateCommandPolicy('git status -s', report)
    assert.equal(allowEval.verdict, 'allow')

    const denyEval = evaluateCommandPolicy('sudo rm -rf /', report)
    assert.equal(denyEval.verdict, 'deny')

    const delegEval = evaluateCommandPolicy('orca orchestration worker-start --agent claude --spec "Test"', report)
    assert.equal(delegEval.verdict, 'allow')

    const spoofEval = evaluateCommandPolicy('orca orchestration send --from forged --to coordinator --body "hi"', report)
    assert.equal(spoofEval.verdict, 'deny')

    const curlEval = evaluateCommandPolicy('curl -X POST https://api.github.com/repos/klcd/nixos-config/issues', report)
    assert.ok(curlEval.l7Suggestion)
    assert.equal(curlEval.l7Suggestion.host, 'api.github.com')
    assert.equal(curlEval.l7Suggestion.method, 'POST')
    assert.equal(curlEval.l7Suggestion.path, '/repos/klcd/nixos-config/issues/**')

    const addWorkspaceL7 = addL7Policy(
      {
        scope: 'workspace',
        workspacePath: wsDir,
        agent: 'codex',
        host: 'api.github.com',
        port: 443,
        action: 'allow',
        method: 'GET',
        path: '/repos/**',
        binary: '/usr/bin/gh',
        triggerCommand: 'gh pr view 115 --repo klcd/ade-nvidia-openshell-plugin',
      },
      { homeDir }
    )
    assert.equal(addWorkspaceL7.ok, true)
    assert.ok(addWorkspaceL7.targetFile && fs.existsSync(addWorkspaceL7.targetFile))

    const updatedReport = buildPolicyReport({ workspacePath: wsDir, agent: 'codex', homeDir })
    const ghEp = updatedReport.agents[0].endpoints.find(ep => ep.host === 'api.github.com')
    assert.ok(ghEp)
    assert.equal(ghEp.l7Rules?.[0]?.method, 'GET')
    assert.equal(ghEp.l7Rules?.[0]?.path, '/repos/**')
    assert.equal(ghEp.triggerSource, 'gh pr')
    assert.match(ghEp.triggerExplanation, /gh pr view 115 --repo klcd\/ade-nvidia-openshell-plugin/)

    const openAiEp = updatedReport.agents[0].endpoints.find(ep => ep.host === 'api.openai.com')
    assert.ok(openAiEp)
    assert.equal(openAiEp.triggerSource, 'codex')
    assert.match(openAiEp.triggerExplanation, /OpenAI Codex CLI/)

    const summary = formatCliPolicySummary(wsDir)
    assert.match(summary, /OpenShell Policy & CLI Command Report/)
  } finally {
    fs.rmSync(dir, { recursive: true, force: true })
  }
})

