import { describe, expect, test } from 'bun:test';
import { StreamSessionTracker } from './session-hibernation.js';

describe('StreamSessionTracker (Claude stream-json)', () => {
  test('tracks session_id, blocks hibernation during turns or UI approvals, and replays control state on wake', () => {
    const tracker = new StreamSessionTracker('claude', [
      '-p',
      '--input-format',
      'stream-json',
      '--output-format',
      'stream-json',
      '--session-id',
      '11111111-2222-3333-4444-555555555555',
    ]);

    expect(tracker.sessionId).toBe('11111111-2222-3333-4444-555555555555');
    expect(tracker.canHibernate()).toBe(true);

    // Host sends initialize + set_permission_mode control requests
    tracker.observeHostFrame(
      JSON.stringify({
        type: 'control_request',
        request_id: 'init_1',
        request: { subtype: 'initialize', systemPrompt: 'test' },
      })
    );
    expect(tracker.canHibernate()).toBe(false); // pendingHostRequests

    const initResp = tracker.observeContainerFrame(
      JSON.stringify({
        type: 'control_response',
        response: { subtype: 'success', request_id: 'init_1', response: { session_state: 'idle' } },
      })
    );
    expect(initResp.suppress).toBe(false);
    expect(tracker.canHibernate()).toBe(true);

    tracker.observeHostFrame(
      JSON.stringify({
        type: 'control_request',
        request_id: 'perm_1',
        request: { subtype: 'set_permission_mode', mode: 'acceptEdits' },
      })
    );
    tracker.observeContainerFrame(
      JSON.stringify({
        type: 'control_response',
        response: { subtype: 'success', request_id: 'perm_1' },
      })
    );

    // Start a user turn
    tracker.observeHostFrame(
      JSON.stringify({
        type: 'user',
        message: { role: 'user', content: 'Run tests' },
      })
    );
    expect(tracker.isTurnActive).toBe(true);
    expect(tracker.canHibernate()).toBe(false);

    // Emit initial system/init frame from container
    const firstSysInit = tracker.observeContainerFrame(
      JSON.stringify({
        type: 'system',
        subtype: 'init',
        session_id: '11111111-2222-3333-4444-555555555555',
      })
    );
    expect(firstSysInit.suppress).toBe(false);

    // Container asks host UI for tool permission / AskUserQuestion mid-turn
    tracker.observeContainerFrame(
      JSON.stringify({
        type: 'control_request',
        request_id: 'ask_ui_1',
        request: { subtype: 'can_use_tool', tool_name: 'AskUserQuestion' },
      })
    );
    expect(tracker.hasPendingDecisions).toBe(true);
    expect(tracker.canHibernate()).toBe(false);

    // Even if turn temporarily paused, pending UI decision keeps hibernation blocked
    tracker.observeHostFrame(
      JSON.stringify({
        type: 'control_response',
        response: { subtype: 'success', request_id: 'ask_ui_1', response: { behavior: 'allow' } },
      })
    );
    expect(tracker.hasPendingDecisions).toBe(false);
    expect(tracker.canHibernate()).toBe(false); // turn still active until result

    // Turn finishes
    tracker.observeContainerFrame(
      JSON.stringify({
        type: 'result',
        subtype: 'success',
        session_id: '11111111-2222-3333-4444-555555555555',
      })
    );
    expect(tracker.isTurnActive).toBe(false);
    expect(tracker.canHibernate()).toBe(true);

    // Build resumed CLI args (replaces --session-id with --resume)
    const resumedArgs = tracker.buildResumedRawArgs([
      '-p',
      '--input-format',
      'stream-json',
      '--output-format',
      'stream-json',
      '--session-id',
      '11111111-2222-3333-4444-555555555555',
    ]);
    expect(resumedArgs).toEqual([
      '-p',
      '--input-format',
      'stream-json',
      '--output-format',
      'stream-json',
      '--resume',
      '11111111-2222-3333-4444-555555555555',
    ]);

    // Warmup replays initialize + set_permission_mode and suppresses synthetic responses + duplicate system/init
    const warmup = tracker.prepareResumeWarmup();
    expect(warmup.waitForWarmup).toBe(true);
    expect(warmup.initialFrames).toHaveLength(2);

    const r1 = tracker.observeContainerFrame(
      JSON.stringify({
        type: 'control_response',
        response: { subtype: 'success', request_id: '__orca_hib_initialize__' },
      })
    );
    expect(r1.suppress).toBe(true);
    expect(r1.warmupComplete).toBe(false);

    const r2 = tracker.observeContainerFrame(
      JSON.stringify({
        type: 'control_response',
        response: { subtype: 'success', request_id: '__orca_hib_set_permission_mode__' },
      })
    );
    expect(r2.suppress).toBe(true);
    expect(r2.warmupComplete).toBe(true);

    const dupInit = tracker.observeContainerFrame(
      JSON.stringify({
        type: 'system',
        subtype: 'init',
        session_id: '11111111-2222-3333-4444-555555555555',
      })
    );
    expect(dupInit.suppress).toBe(true);
  });
});

describe('StreamSessionTracker (Codex app-server)', () => {
  test('tracks threadId, blocks hibernation during turns or approvals, and runs 2-stage thread/resume warmup', () => {
    const tracker = new StreamSessionTracker('codex', ['app-server']);
    expect(tracker.canHibernate()).toBe(false);

    // 1. initialize
    tracker.observeHostFrame(
      JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: { clientInfo: { name: 'orca', version: '1.0.0' } },
      })
    );
    tracker.observeContainerFrame(
      JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        result: { userAgent: 'codex' },
      })
    );
    tracker.observeHostFrame(JSON.stringify({ jsonrpc: '2.0', method: 'initialized', params: {} }));
    expect(tracker.canHibernate()).toBe(false); // no thread yet

    // 2. thread/start
    tracker.observeHostFrame(
      JSON.stringify({
        jsonrpc: '2.0',
        id: 2,
        method: 'thread/start',
        params: { cwd: '/sandbox/project' },
      })
    );
    tracker.observeContainerFrame(
      JSON.stringify({
        jsonrpc: '2.0',
        id: 2,
        result: { thread: { id: 'thr_abc123' } },
      })
    );
    expect(tracker.sessionId).toBe('thr_abc123');
    expect(tracker.canHibernate()).toBe(true);

    // 3. turn/start + server approval request
    tracker.observeHostFrame(
      JSON.stringify({
        jsonrpc: '2.0',
        id: 3,
        method: 'turn/start',
        params: { threadId: 'thr_abc123', input: [{ type: 'text', text: 'hello' }] },
      })
    );
    tracker.observeContainerFrame(JSON.stringify({ jsonrpc: '2.0', id: 3, result: { turn: { id: 'turn_1' } } }));
    expect(tracker.canHibernate()).toBe(false);

    // Server sends approval request to client
    tracker.observeContainerFrame(
      JSON.stringify({
        jsonrpc: '2.0',
        id: 'srv_req_9',
        method: 'item/commandExecution/requestApproval',
        params: { command: 'npm publish' },
      })
    );
    expect(tracker.hasPendingDecisions).toBe(true);
    expect(tracker.canHibernate()).toBe(false);

    // Client responds to approval
    tracker.observeHostFrame(
      JSON.stringify({
        jsonrpc: '2.0',
        id: 'srv_req_9',
        result: { decision: 'accept' },
      })
    );
    expect(tracker.hasPendingDecisions).toBe(false);
    expect(tracker.canHibernate()).toBe(false); // turn still active

    // Turn completes
    tracker.observeContainerFrame(
      JSON.stringify({
        jsonrpc: '2.0',
        method: 'turn/completed',
        params: { threadId: 'thr_abc123', turn: { id: 'turn_1' } },
      })
    );
    expect(tracker.canHibernate()).toBe(true);

    // 4. Wake warmup: initialize -> initialized + thread/resume (excludeTurns: true)
    const warmup = tracker.prepareResumeWarmup();
    expect(warmup.waitForWarmup).toBe(true);
    expect(warmup.initialFrames).toHaveLength(1);
    const initFrame = JSON.parse(warmup.initialFrames[0]);
    expect(initFrame.method).toBe('initialize');
    expect(initFrame.id).toBe('__orca_hib_init__');

    // Container responds to synthetic initialize
    const step1 = tracker.observeContainerFrame(
      JSON.stringify({
        jsonrpc: '2.0',
        id: '__orca_hib_init__',
        result: { userAgent: 'codex' },
      })
    );
    expect(step1.suppress).toBe(true);
    expect(step1.warmupComplete).toBe(false);
    expect(step1.followUpFrames).toHaveLength(2);
    expect(JSON.parse(step1.followUpFrames[0]).method).toBe('initialized');
    const resumeReq = JSON.parse(step1.followUpFrames[1]);
    expect(resumeReq.method).toBe('thread/resume');
    expect(resumeReq.params).toEqual({ threadId: 'thr_abc123', excludeTurns: true });

    // Any intermediate notification during warmup is suppressed
    const interimNotif = tracker.observeContainerFrame(
      JSON.stringify({
        jsonrpc: '2.0',
        method: 'thread/started',
        params: { thread: { id: 'thr_abc123' } },
      })
    );
    expect(interimNotif.suppress).toBe(true);
    expect(interimNotif.warmupComplete).toBe(false);

    // Container responds to synthetic thread/resume -> warmup complete!
    const step2 = tracker.observeContainerFrame(
      JSON.stringify({
        jsonrpc: '2.0',
        id: '__orca_hib_resume__',
        result: { thread: { id: 'thr_abc123' } },
      })
    );
    expect(step2.suppress).toBe(true);
    expect(step2.warmupComplete).toBe(true);
  });
});
