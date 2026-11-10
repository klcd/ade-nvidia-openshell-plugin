import { strict as assert } from 'node:assert'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { test } from 'node:test'
import activate, { bridgeCommand, formatCliPolicySummary } from './worker.ts'
import {
  addL7Policy,
  buildPolicyReport,
  evaluateCommandPolicy,
  getSandboxIdleTimeoutSeconds,
  parsePermissionYaml,
  pruneSandboxRegistryEntry,
  recordSessionEgressRule,
  removeTemporaryL7Rule,
  resolveCurrentTabSandbox,
  setSandboxIdleTimeoutSeconds,
} from './policy-inspector.ts'

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
  const beforeDef = process.env.ORCA_OPENSHELL_DEFAULT_ENABLED
  process.env.ORCA_OPENSHELL_BRIDGE_BIN_DIR = '/definitely-not-installed-orca-bridge'
  process.env.ORCA_OPENSHELL_DEFAULT_ENABLED = '1'
  try {
    const result = handler({ agent: 'codex', workspaceId: 'ws', command: 'codex', env: {} }, x => x)
    assert.match(result.deny, /missing/)
  } finally {
    if (before === undefined) delete process.env.ORCA_OPENSHELL_BRIDGE_BIN_DIR
    else process.env.ORCA_OPENSHELL_BRIDGE_BIN_DIR = before
    if (beforeDef === undefined) delete process.env.ORCA_OPENSHELL_DEFAULT_ENABLED
    else process.env.ORCA_OPENSHELL_DEFAULT_ENABLED = beforeDef
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
  const oldDef = process.env.ORCA_OPENSHELL_DEFAULT_ENABLED
  process.env.ORCA_OPENSHELL_BRIDGE_BIN_DIR = dir
  process.env.ORCA_OPENSHELL_POLICY_DIR = policies
  process.env.ORCA_OPENSHELL_DEFAULT_ENABLED = '1'
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
    if (oldDef === undefined) delete process.env.ORCA_OPENSHELL_DEFAULT_ENABLED
    else process.env.ORCA_OPENSHELL_DEFAULT_ENABLED = oldDef
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
    assert.equal(report.defaultSandboxEnabled, false)
    assert.equal(report.sandboxEnabled, false)

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

test('sandbox mode is off by default, configurable globally, and inherited per-worktree', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'orca-sandbox-toggle-test-'))
  const wtA = path.join(dir, 'worktree-a')
  const wtB = path.join(dir, 'worktree-b')
  const childGitWt = path.join(dir, 'worktree-a-git-child')
  const childOrcaWt = path.join(dir, 'worktree-a-orca-child')
  const childSubdir = path.join(wtA, 'packages', 'subpkg')
  fs.mkdirSync(path.join(wtA, '.git', 'worktrees', 'child-wt'), { recursive: true })
  fs.mkdirSync(wtB, { recursive: true })
  fs.mkdirSync(childGitWt, { recursive: true })
  fs.mkdirSync(childOrcaWt, { recursive: true })
  fs.mkdirSync(childSubdir, { recursive: true })
  fs.writeFileSync(
    path.join(childGitWt, '.git'),
    `gitdir: ${path.join(wtA, '.git', 'worktrees', 'child-wt')}\n`
  )

  const binDir = path.join(dir, 'bin')
  const policyDir = path.join(dir, 'policies')
  fs.mkdirSync(binDir, { recursive: true })
  fs.mkdirSync(policyDir, { recursive: true })
  fs.writeFileSync(path.join(binDir, 'claude-box'), '#!/bin/sh\n', { mode: 0o755 })
  fs.writeFileSync(path.join(policyDir, 'claude.json'), '{}')

  const modeFile = path.join(dir, 'sandbox-mode.json')
  const prevModeFile = process.env.ORCA_OPENSHELL_MODE_FILE
  const prevBinDir = process.env.ORCA_OPENSHELL_BRIDGE_BIN_DIR
  const prevPolicyDir = process.env.ORCA_OPENSHELL_POLICY_DIR
  const prevDef = process.env.ORCA_OPENSHELL_DEFAULT_ENABLED
  process.env.ORCA_OPENSHELL_MODE_FILE = modeFile
  process.env.ORCA_OPENSHELL_BRIDGE_BIN_DIR = binDir
  process.env.ORCA_OPENSHELL_POLICY_DIR = policyDir
  delete process.env.ORCA_OPENSHELL_DEFAULT_ENABLED
  try {
    let handler: ((event: any, next: (event?: any) => any) => any) | undefined
    const panelHandlers = new Map<string, (input: any) => any>()
    activate({
      hooks: { on: (_name: string, fn: typeof handler) => { handler = fn } },
      panels: { handle: (name: string, fn: (input: any) => any) => { panelHandlers.set(name, fn) } },
      log() {},
    } as any)
    assert.ok(handler)
    assert.ok(panelHandlers.has('setSandboxMode'))
    assert.ok(panelHandlers.has('setDefaultSandboxMode'))

    // Unconfigured worktrees default to OFF (Host Mode)
    const initialReportB = buildPolicyReport({ workspacePath: wtB, agent: 'claude' })
    assert.equal(initialReportB.defaultSandboxEnabled, false)
    assert.equal(initialReportB.sandboxEnabled, false)

    // Global default can be configured to ON via setDefaultSandboxMode
    const setDefaultMode = panelHandlers.get('setDefaultSandboxMode')!
    const afterDefaultOn = await setDefaultMode({ enabled: true, workspacePath: wtB, agent: 'claude' })
    assert.equal(afterDefaultOn.defaultSandboxEnabled, true)
    assert.equal(afterDefaultOn.sandboxEnabled, true)

    const setMode = panelHandlers.get('setSandboxMode')!
    const disabledReportA = await setMode({
      enabled: false,
      workspacePath: wtA,
      workspaceId: `repo-a::${wtA}`,
      parentPaths: { [childOrcaWt]: wtA },
      agent: 'claude',
    })
    assert.equal(disabledReportA.sandboxEnabled, false)
    assert.equal(disabledReportA.sandboxInheritedFrom, null)

    // Worktree B remains sandboxed via defaultEnabled=true
    const reportB = buildPolicyReport({ workspacePath: wtB, agent: 'claude' })
    assert.equal(reportB.sandboxEnabled, true)

    // All child workspaces of Worktree A inherit sandboxEnabled: false
    const gitChildReport = buildPolicyReport({ workspacePath: childGitWt, agent: 'claude' })
    assert.equal(gitChildReport.sandboxEnabled, false)
    assert.ok(gitChildReport.sandboxInheritedFrom?.endsWith('worktree-a'))

    const orcaChildReport = buildPolicyReport({ workspacePath: childOrcaWt, agent: 'claude' })
    assert.equal(orcaChildReport.sandboxEnabled, false)
    assert.ok(orcaChildReport.sandboxInheritedFrom?.endsWith('worktree-a'))

    const subdirChildReport = buildPolicyReport({ workspacePath: childSubdir, agent: 'claude' })
    assert.equal(subdirChildReport.sandboxEnabled, false)
    assert.ok(subdirChildReport.sandboxInheritedFrom?.endsWith('worktree-a'))

    // Launching in Worktree A or its child worktree runs directly on host
    const launchChildRes = handler({
      agent: 'claude',
      workspaceId: `repo-a::${childGitWt}`,
      command: 'claude --dangerously-skip-permissions',
      env: { OPENSHELL_BRIDGE_REQUIRED: '1' },
    }, x => x)
    assert.equal(launchChildRes.command, 'claude --dangerously-skip-permissions')
    assert.equal(launchChildRes.env.OPENSHELL_SANDBOX_DISABLED, '1')
    assert.equal(launchChildRes.env.OPENSHELL_BRIDGE_REQUIRED, undefined)

    // Launching in Worktree B still uses claude-box
    const launchBRes = handler({
      agent: 'claude',
      workspaceId: `repo-b::${wtB}`,
      command: 'claude --dangerously-skip-permissions',
      env: {},
    }, x => x)
    assert.match(launchBRes.command, /claude-box' --dangerously-skip-permissions$/)
    assert.equal(launchBRes.env.OPENSHELL_BRIDGE_REQUIRED, '1')

    const evalRes = evaluateCommandPolicy('git status', disabledReportA)
    assert.ok(evalRes.sandboxChecks.some(c => c.layer === 'OpenShell Sandbox' && c.status === 'warn'))

    // Even if a child had an explicit override, toggling parent Worktree A back on syncs children too
    await setMode({ enabled: false, workspacePath: childOrcaWt, agent: 'claude' })
    const enabledReportA = await setMode({ enabled: true, workspacePath: wtA, agent: 'claude' })
    assert.equal(enabledReportA.sandboxEnabled, true)
    assert.equal(buildPolicyReport({ workspacePath: childOrcaWt, agent: 'claude' }).sandboxEnabled, true)
    assert.equal(buildPolicyReport({ workspacePath: childGitWt, agent: 'claude' }).sandboxEnabled, true)
  } finally {
    if (prevModeFile === undefined) delete process.env.ORCA_OPENSHELL_MODE_FILE
    else process.env.ORCA_OPENSHELL_MODE_FILE = prevModeFile
    if (prevBinDir === undefined) delete process.env.ORCA_OPENSHELL_BRIDGE_BIN_DIR
    else process.env.ORCA_OPENSHELL_BRIDGE_BIN_DIR = prevBinDir
    if (prevPolicyDir === undefined) delete process.env.ORCA_OPENSHELL_POLICY_DIR
    else process.env.ORCA_OPENSHELL_POLICY_DIR = prevPolicyDir
    if (prevDef === undefined) delete process.env.ORCA_OPENSHELL_DEFAULT_ENABLED
    else process.env.ORCA_OPENSHELL_DEFAULT_ENABLED = prevDef
    fs.rmSync(dir, { recursive: true, force: true })
  }
})

test('temporary L7 rule shows Temporary tag in egress report and promotes cleanly to Project rules', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'orca-temp-egress-test-'))
  const homeDir = path.join(dir, 'home')
  const wsDir = path.join(dir, 'workspace')
  const sessFile = path.join(dir, 'session-egress.json')
  fs.mkdirSync(homeDir, { recursive: true })
  fs.mkdirSync(wsDir, { recursive: true })

  const prevSessFile = process.env.ORCA_OPENSHELL_SESSION_EGRESS_FILE
  process.env.ORCA_OPENSHELL_SESSION_EGRESS_FILE = sessFile
  try {
    const tempRes = addL7Policy(
      {
        scope: 'session',
        workspacePath: wsDir,
        agent: 'antigravity',
        host: 'pypi.org',
        port: 443,
        action: 'allow',
        method: 'GET',
        path: '/simple/**',
        binary: '*',
        triggerCommand: 'pip install pydantic',
      },
      { homeDir }
    )
    assert.equal(tempRes.ok, true)

    const reportWithTemp = buildPolicyReport({ workspacePath: wsDir, agent: 'antigravity', homeDir })
    const tempEp = reportWithTemp.agents[0].endpoints.find(ep => ep.host === 'pypi.org')
    assert.ok(tempEp)
    assert.equal(tempEp.temporary, true)
    assert.equal(tempEp.ruleScope, 'temporary')
    assert.equal(tempEp.l7Rules?.[0]?.path, '/simple/**')

    const projRes = addL7Policy(
      {
        scope: 'workspace',
        workspacePath: wsDir,
        agent: 'antigravity',
        host: 'pypi.org',
        port: 443,
        action: 'allow',
        method: 'GET',
        path: '/simple/**',
        binary: '*',
        triggerCommand: 'pip install pydantic',
      },
      { homeDir }
    )
    assert.equal(projRes.ok, true)
    assert.ok(fs.existsSync(path.join(wsDir, '.agents', 'policies', 'l7-custom.json')))

    const reportAfterPromote = buildPolicyReport({ workspacePath: wsDir, agent: 'antigravity', homeDir })
    const projEp = reportAfterPromote.agents[0].endpoints.find(ep => ep.host === 'pypi.org')
    assert.ok(projEp)
    assert.equal(projEp.temporary, false)
    assert.equal(projEp.ruleScope, 'project')
    assert.equal(projEp.sourcePath, '.agents/policies/l7-custom.json')

    // Verify every field in report and addL7Policy responses satisfies Orca's strict isJsonValue check (no undefined properties)
    const assertStrictJson = (val: unknown, keyPath = '$'): void => {
      if (val === null || typeof val === 'string' || typeof val === 'boolean') return
      if (typeof val === 'number') {
        assert.ok(Number.isFinite(val), `Non-finite number at ${keyPath}`)
        return
      }
      assert.notEqual(val, undefined, `Undefined value at ${keyPath}`)
      assert.equal(typeof val, 'object', `Non-JSON type ${typeof val} at ${keyPath}`)
      if (Array.isArray(val)) {
        val.forEach((item, idx) => assertStrictJson(item, `${keyPath}[${idx}]`))
        return
      }
      for (const [k, v] of Object.entries(val as Record<string, unknown>)) {
        assertStrictJson(v, `${keyPath}.${k}`)
      }
    }
    assertStrictJson(tempRes)
    assertStrictJson(reportWithTemp)
    assertStrictJson(projRes)
    assertStrictJson(reportAfterPromote)
  } finally {
    if (prevSessFile === undefined) delete process.env.ORCA_OPENSHELL_SESSION_EGRESS_FILE
    else process.env.ORCA_OPENSHELL_SESSION_EGRESS_FILE = prevSessFile
    fs.rmSync(dir, { recursive: true, force: true })
  }
})

test('setSandboxIdleTimeout persists timeout and survives setSandboxMode toggles', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'orca-idle-timeout-test-'))
  const wsDir = path.join(dir, 'workspace')
  fs.mkdirSync(wsDir, { recursive: true })
  const modeFile = path.join(dir, 'sandbox-mode.json')
  const prevModeFile = process.env.ORCA_OPENSHELL_MODE_FILE
  process.env.ORCA_OPENSHELL_MODE_FILE = modeFile
  try {
    const panelHandlers = new Map<string, (input: any) => any>()
    activate({
      hooks: { on() {} },
      panels: { handle: (name: string, fn: (input: any) => any) => { panelHandlers.set(name, fn) } },
      log() {},
    } as any)

    assert.ok(panelHandlers.has('setSandboxIdleTimeout'))
    assert.ok(panelHandlers.has('pauseSandbox'))
    assert.ok(panelHandlers.has('resumeSandbox'))

    const initialReport = buildPolicyReport({ workspacePath: wsDir, agent: 'claude' })
    assert.equal(initialReport.sandboxIdleTimeoutSeconds, 300)

    const setIdle = panelHandlers.get('setSandboxIdleTimeout')!
    const updatedReport = await setIdle({ seconds: 180, workspacePath: wsDir, agent: 'claude' })
    assert.equal(updatedReport.sandboxIdleTimeoutSeconds, 180)

    // Toggling per-worktree sandbox mode preserves idleTimeoutSeconds
    const setMode = panelHandlers.get('setSandboxMode')!
    const toggledReport = await setMode({ enabled: false, workspacePath: wsDir, agent: 'claude' })
    assert.equal(toggledReport.sandboxEnabled, false)
    assert.equal(toggledReport.sandboxIdleTimeoutSeconds, 180)

    // Setting 0 disables auto-pause
    const disabledIdleReport = await setIdle({ seconds: 0, workspacePath: wsDir, agent: 'claude' })
    assert.equal(disabledIdleReport.sandboxIdleTimeoutSeconds, 0)
  } finally {
    if (prevModeFile === undefined) delete process.env.ORCA_OPENSHELL_MODE_FILE
    else process.env.ORCA_OPENSHELL_MODE_FILE = prevModeFile
    fs.rmSync(dir, { recursive: true, force: true })
  }
})

test('resolveCurrentTabSandbox returns only the sandbox running in the active tab', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'orca-tab-sandbox-test-'))
  const wsA = path.join(dir, 'ade-nvidia-openshell-plugin')
  const wsB = path.join(dir, 'other-repo')
  fs.mkdirSync(wsA, { recursive: true })
  fs.mkdirSync(wsB, { recursive: true })
  const regFile = path.join(dir, 'sandbox-registry.json')
  const prevReg = process.env.ORCA_OPENSHELL_REGISTRY_FILE
  process.env.ORCA_OPENSHELL_REGISTRY_FILE = regFile
  try {
    fs.writeFileSync(
      regFile,
      JSON.stringify({
        entries: [
          {
            sandboxName: 'ag-ade-nv-tab1',
            agent: 'antigravity',
            workspacePath: wsA,
            agentSessionId: 'antigravity_tab_one',
            pid: process.pid,
          },
          {
            sandboxName: 'ag-ade-nv-tab2',
            agent: 'antigravity',
            workspacePath: wsA,
            agentSessionId: 'antigravity_tab_two',
            pid: process.pid,
          },
          {
            sandboxName: 'ag-other-repo1',
            agent: 'antigravity',
            workspacePath: wsB,
            agentSessionId: 'antigravity_other_repo',
            pid: process.pid,
          },
        ],
      })
    )

    const allSandboxes = [
      { name: 'ag-orca-c-probe1', created: '2026-11-08 20:34:05', phase: 'Ready', agent: 'antigravity' },
      { name: 'ag-ade-nv-tab1', created: '2026-11-09 19:00:00', phase: 'Stopped', agent: 'antigravity' },
      { name: 'ag-ade-nv-tab2', created: '2026-11-09 19:30:00', phase: 'Ready', agent: 'antigravity' },
      { name: 'ag-other-repo1', created: '2026-11-09 19:45:00', phase: 'Ready', agent: 'antigravity' },
      { name: 'cc-ade-nv-claude1', created: '2026-11-09 19:50:00', phase: 'Ready', agent: 'claude' },
    ]

    // Active tab 1 in wsA -> only ag-ade-nv-tab1
    const tab1Result = resolveCurrentTabSandbox({
      allSandboxes,
      selectedWorkspace: { id: `local::${wsA}`, name: 'ade-nvidia-openshell-plugin', path: wsA, branch: 'master' },
      currentAgent: 'antigravity',
      activeAgentSessions: [
        {
          agent: 'antigravity',
          state: 'working',
          conversationName: 'Tab 1',
          paneKey: 'structured-agent-session-antigravity_tab_one:leaf-1',
          updatedAt: 200,
        },
        {
          agent: 'antigravity',
          state: 'done',
          conversationName: 'Tab 2',
          paneKey: 'structured-agent-session-antigravity_tab_two:leaf-2',
          updatedAt: 100,
        },
      ],
      homeDir: dir,
    })
    assert.deepEqual(tab1Result.map(s => s.name), ['ag-ade-nv-tab1'])

    // Switching focus to tab 2 in wsA -> only ag-ade-nv-tab2
    const tab2Result = resolveCurrentTabSandbox({
      allSandboxes,
      selectedWorkspace: { id: `local::${wsA}`, name: 'ade-nvidia-openshell-plugin', path: wsA, branch: 'master' },
      currentAgent: 'antigravity',
      activeAgentSessions: [
        {
          agent: 'antigravity',
          state: 'working',
          conversationName: 'Tab 2',
          paneKey: 'structured-agent-session-antigravity_tab_two:leaf-2',
          updatedAt: 300,
        },
      ],
      homeDir: dir,
    })
    assert.deepEqual(tab2Result.map(s => s.name), ['ag-ade-nv-tab2'])

    // Workspace with no sandbox for the active tab -> empty array (never leaks other tabs/repos)
    const emptyTabResult = resolveCurrentTabSandbox({
      allSandboxes,
      selectedWorkspace: { id: `local::${wsA}`, name: 'ade-nvidia-openshell-plugin', path: wsA, branch: 'master' },
      currentAgent: 'antigravity',
      activeAgentSessions: [
        {
          agent: 'antigravity',
          state: 'done',
          conversationName: 'New Idle Tab',
          paneKey: 'structured-agent-session-antigravity_brand_new_tab:leaf-3',
          updatedAt: 400,
        },
      ],
      homeDir: dir,
    })
    assert.deepEqual(emptyTabResult, [])
  } finally {
    if (prevReg === undefined) delete process.env.ORCA_OPENSHELL_REGISTRY_FILE
    else process.env.ORCA_OPENSHELL_REGISTRY_FILE = prevReg
    fs.rmSync(dir, { recursive: true, force: true })
  }
})

test('Auto-Pause When Idle is strictly per-tab and Temporary L7 rules are scoped per sandboxName', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'orca-per-tab-isolation-test-'))
  const wsDir = path.join(dir, 'workspace')
  fs.mkdirSync(wsDir, { recursive: true })
  const modeFile = path.join(dir, 'sandbox-mode.json')
  const regFile = path.join(dir, 'sandbox-registry.json')
  const sessFile = path.join(dir, 'session-egress.json')

  const prevMode = process.env.ORCA_OPENSHELL_MODE_FILE
  const prevReg = process.env.ORCA_OPENSHELL_REGISTRY_FILE
  const prevSess = process.env.ORCA_OPENSHELL_SESSION_EGRESS_FILE
  process.env.ORCA_OPENSHELL_MODE_FILE = modeFile
  process.env.ORCA_OPENSHELL_REGISTRY_FILE = regFile
  process.env.ORCA_OPENSHELL_SESSION_EGRESS_FILE = sessFile

  try {
    fs.writeFileSync(
      regFile,
      JSON.stringify({
        entries: [
          {
            sandboxName: 'ag-ws-tab1',
            agent: 'antigravity',
            workspacePath: wsDir,
            agentSessionId: 'antigravity_tab_alpha',
            pid: process.pid,
          },
          {
            sandboxName: 'ag-ws-tab2',
            agent: 'antigravity',
            workspacePath: wsDir,
            agentSessionId: 'antigravity_tab_beta',
            pid: process.pid,
          },
        ],
      })
    )

    // 1. Per-tab Auto-Pause When Idle: setting Tab 1 to 60s leaves Tab 2 at default 300s
    setSandboxIdleTimeoutSeconds(
      60,
      {
        sandboxName: 'ag-ws-tab1',
        paneKey: 'structured-agent-session-antigravity_tab_alpha:leaf-1',
        workspacePath: wsDir,
        agent: 'antigravity',
      },
      dir
    )
    assert.equal(
      getSandboxIdleTimeoutSeconds(
        { sandboxName: 'ag-ws-tab1', paneKey: 'structured-agent-session-antigravity_tab_alpha:leaf-1' },
        dir
      ),
      60
    )
    assert.equal(
      getSandboxIdleTimeoutSeconds(
        { sandboxName: 'ag-ws-tab2', paneKey: 'structured-agent-session-antigravity_tab_beta:leaf-2' },
        dir
      ),
      300
    )

    // Setting Tab 2 to Off (0s) does not affect Tab 1 (60s)
    setSandboxIdleTimeoutSeconds(
      0,
      {
        sandboxName: 'ag-ws-tab2',
        paneKey: 'structured-agent-session-antigravity_tab_beta:leaf-2',
        workspacePath: wsDir,
        agent: 'antigravity',
      },
      dir
    )
    assert.equal(getSandboxIdleTimeoutSeconds({ sandboxName: 'ag-ws-tab1' }, dir), 60)
    assert.equal(getSandboxIdleTimeoutSeconds({ sandboxName: 'ag-ws-tab2' }, dir), 0)

    // Deleting Tab 1's sandbox prunes sandbox:ag-ws-tab1 while keeping session:antigravity_tab_alpha for seamless recreate
    pruneSandboxRegistryEntry('ag-ws-tab1', dir)
    assert.equal(
      getSandboxIdleTimeoutSeconds({ agentSessionId: 'antigravity_tab_alpha' }, dir),
      60
    )

    // 2. Per-sandbox Temporary L7 egress rules: two sibling tabs in same worktree stay isolated
    recordSessionEgressRule(
      {
        sandboxName: 'ag-ws-tab1',
        workspacePath: wsDir,
        agent: 'antigravity',
        ruleName: 'crates_io_l7',
        host: 'crates.io',
        port: 443,
        action: 'allow',
        method: 'GET',
        path: '/api/**',
        binary: '*',
        createdAt: new Date().toISOString(),
      },
      dir
    )
    recordSessionEgressRule(
      {
        sandboxName: 'ag-ws-tab2',
        workspacePath: wsDir,
        agent: 'antigravity',
        ruleName: 'pypi_org_l7',
        host: 'pypi.org',
        port: 443,
        action: 'allow',
        method: 'GET',
        path: '/simple/**',
        binary: '*',
        createdAt: new Date().toISOString(),
      },
      dir
    )

    // Removing crates.io on ag-ws-tab2 fails (does not exist on tab2), while removing on ag-ws-tab1 succeeds without touching tab2
    const wrongTabRemove = removeTemporaryL7Rule(
      { sandboxName: 'ag-ws-tab2', workspacePath: wsDir, host: 'crates.io', port: 443 },
      { homeDir: dir }
    )
    assert.equal(wrongTabRemove.ok, false)

    const rightTabRemove = removeTemporaryL7Rule(
      { sandboxName: 'ag-ws-tab1', workspacePath: wsDir, host: 'crates.io', port: 443 },
      { homeDir: dir }
    )
    assert.equal(rightTabRemove.ok, true)

    const remaining = JSON.parse(fs.readFileSync(sessFile, 'utf8')).entries
    assert.equal(remaining.length, 1)
    assert.equal(remaining[0].sandboxName, 'ag-ws-tab2')
    assert.equal(remaining[0].host, 'pypi.org')
  } finally {
    if (prevMode === undefined) delete process.env.ORCA_OPENSHELL_MODE_FILE
    else process.env.ORCA_OPENSHELL_MODE_FILE = prevMode
    if (prevReg === undefined) delete process.env.ORCA_OPENSHELL_REGISTRY_FILE
    else process.env.ORCA_OPENSHELL_REGISTRY_FILE = prevReg
    if (prevSess === undefined) delete process.env.ORCA_OPENSHELL_SESSION_EGRESS_FILE
    else process.env.ORCA_OPENSHELL_SESSION_EGRESS_FILE = prevSess
    fs.rmSync(dir, { recursive: true, force: true })
  }
})




