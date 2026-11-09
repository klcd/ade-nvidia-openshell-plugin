import type { AgentType } from '../types.js';

const CLAUDE_REPLAYABLE_SUBTYPES = [
  'initialize',
  'set_permission_mode',
  'set_model',
  'set_max_thinking_tokens',
] as const;

const CODEX_INTERNAL_INIT_ID = '__orca_hib_init__';
const CODEX_INTERNAL_RESUME_ID = '__orca_hib_resume__';

/**
 * Tracks NDJSON / JSON-RPC protocol state for Claude (`stream-json`) and Codex (`app-server`)
 * so the host bridge knows:
 * 1. When a session is genuinely idle between turns (and NOT waiting on a mid-turn UI approval/dialog).
 * 2. Which session/thread ID and initialization parameters to replay when waking a stopped sandbox.
 */
export class StreamSessionTracker {
  private turnActive = false;
  private readonly pendingHostRequests = new Set<string>();
  private readonly pendingContainerRequests = new Set<string>();

  // Claude stream-json state
  private claudeSessionId: string | null = null;
  private emittedClaudeSystemInit = false;
  private resumedAtLeastOnce = false;
  private readonly claudeControlConfigs = new Map<string, Record<string, unknown>>();
  private readonly swallowedClaudeControlIds = new Set<string>();

  // Codex app-server state
  private codexInitParams: Record<string, unknown> | null = null;
  private codexThreadId: string | null = null;
  private codexWarmupStage: 'none' | 'awaiting_init' | 'awaiting_resume' = 'none';

  constructor(
    public readonly agentType: AgentType,
    initialArgs: string[] = []
  ) {
    if (agentType === 'claude') {
      this.claudeSessionId = StreamSessionTracker.extractClaudeSessionFlag(initialArgs);
    }
  }

  private static extractClaudeSessionFlag(args: string[]): string | null {
    for (let i = 0; i < args.length; i++) {
      const arg = args[i];
      if ((arg === '--session-id' || arg === '--resume' || arg === '-r') && args[i + 1]) {
        return args[i + 1];
      }
      if (arg.startsWith('--session-id=')) return arg.slice('--session-id='.length);
      if (arg.startsWith('--resume=')) return arg.slice('--resume='.length);
    }
    return null;
  }

  public get sessionId(): string | null {
    return this.agentType === 'claude' ? this.claudeSessionId : this.codexThreadId;
  }

  public get isTurnActive(): boolean {
    return this.turnActive;
  }

  public get hasPendingDecisions(): boolean {
    return this.pendingContainerRequests.size > 0;
  }

  public canHibernate(): boolean {
    if (this.turnActive) return false;
    if (this.pendingContainerRequests.size > 0) return false;
    if (this.pendingHostRequests.size > 0) return false;
    if (this.agentType === 'claude') {
      return Boolean(this.claudeSessionId);
    }
    if (this.agentType === 'codex') {
      return Boolean(this.codexInitParams && this.codexThreadId);
    }
    return false;
  }

  public observeHostFrame(rawLine: string): void {
    const trimmed = rawLine.trim();
    if (!trimmed) return;
    let obj: Record<string, any>;
    try {
      obj = JSON.parse(trimmed);
    } catch {
      return;
    }
    if (!obj || typeof obj !== 'object') return;

    if (this.agentType === 'claude') {
      if (obj.type === 'user') {
        this.turnActive = true;
      } else if (obj.type === 'control_request') {
        const reqId = typeof obj.request_id === 'string' ? obj.request_id : '';
        if (reqId) this.pendingHostRequests.add(reqId);
        const subtype = obj.request?.subtype;
        if (
          typeof subtype === 'string' &&
          (CLAUDE_REPLAYABLE_SUBTYPES as readonly string[]).includes(subtype) &&
          obj.request &&
          typeof obj.request === 'object'
        ) {
          this.claudeControlConfigs.set(subtype, { ...obj.request });
        }
      } else if (obj.type === 'control_response') {
        const reqId = obj.response?.request_id ?? obj.request_id;
        if (typeof reqId === 'string') {
          this.pendingContainerRequests.delete(reqId);
        }
      }
      return;
    }

    if (this.agentType === 'codex') {
      const hasMethod = typeof obj.method === 'string' && obj.method.length > 0;
      const hasId = obj.id !== undefined && obj.id !== null;
      if (hasMethod) {
        if (hasId) this.pendingHostRequests.add(String(obj.id));
        if (obj.method === 'initialize') {
          this.codexInitParams =
            obj.params && typeof obj.params === 'object' ? { ...obj.params } : {};
        } else if (obj.method === 'thread/start' || obj.method === 'thread/resume') {
          if (typeof obj.params?.threadId === 'string' && obj.params.threadId) {
            this.codexThreadId = obj.params.threadId;
          }
        } else if (obj.method === 'turn/start') {
          this.turnActive = true;
          if (typeof obj.params?.threadId === 'string' && obj.params.threadId) {
            this.codexThreadId = obj.params.threadId;
          }
        }
      } else if (hasId) {
        // Response to a server->client request (e.g. command approval or user input)
        this.pendingContainerRequests.delete(String(obj.id));
      }
    }
  }

  /**
   * Inspects a container->host NDJSON frame.
   * Returns `{ suppress: true, followUpFrames }` when the frame belongs to an internal
   * post-hibernation warmup handshake and must NOT be forwarded to Orca's stdout.
   */
  public observeContainerFrame(
    rawLine: string,
    isResumedSpawn = false
  ): { suppress: boolean; followUpFrames: string[]; warmupComplete: boolean } {
    const trimmed = rawLine.trim();
    if (!trimmed) {
      return { suppress: false, followUpFrames: [], warmupComplete: this.codexWarmupStage === 'none' };
    }
    let obj: Record<string, any>;
    try {
      obj = JSON.parse(trimmed);
    } catch {
      return { suppress: false, followUpFrames: [], warmupComplete: this.codexWarmupStage === 'none' };
    }
    if (!obj || typeof obj !== 'object') {
      return { suppress: false, followUpFrames: [], warmupComplete: this.codexWarmupStage === 'none' };
    }

    if (this.agentType === 'claude') {
      if (typeof obj.session_id === 'string' && obj.session_id) {
        this.claudeSessionId = obj.session_id;
      }
      if (obj.type === 'control_response') {
        const reqId = obj.response?.request_id ?? obj.request_id;
        if (typeof reqId === 'string') {
          if (this.swallowedClaudeControlIds.has(reqId)) {
            this.swallowedClaudeControlIds.delete(reqId);
            return { suppress: true, followUpFrames: [], warmupComplete: this.swallowedClaudeControlIds.size === 0 };
          }
          this.pendingHostRequests.delete(reqId);
        }
      }
      if (obj.type === 'system' && obj.subtype === 'init') {
        if ((isResumedSpawn || this.resumedAtLeastOnce) && this.emittedClaudeSystemInit) {
          return { suppress: true, followUpFrames: [], warmupComplete: this.swallowedClaudeControlIds.size === 0 };
        }
        this.emittedClaudeSystemInit = true;
      }
      if (obj.type === 'control_request' && typeof obj.request_id === 'string') {
        this.pendingContainerRequests.add(obj.request_id);
      }
      if (obj.type === 'result') {
        this.turnActive = false;
      }
      if (obj.type === 'system' && obj.subtype === 'session_state_changed') {
        if (obj.state === 'idle') this.turnActive = false;
        else if (obj.state === 'running' || obj.state === 'working') this.turnActive = true;
      }
      return { suppress: false, followUpFrames: [], warmupComplete: this.swallowedClaudeControlIds.size === 0 };
    }

    if (this.agentType === 'codex') {
      const hasMethod = typeof obj.method === 'string' && obj.method.length > 0;
      const hasId = obj.id !== undefined && obj.id !== null;
      const idStr = hasId ? String(obj.id) : '';

      if (this.codexWarmupStage !== 'none') {
        if (!hasMethod && idStr === CODEX_INTERNAL_INIT_ID) {
          this.codexWarmupStage = 'awaiting_resume';
          return {
            suppress: true,
            followUpFrames: [
              JSON.stringify({ jsonrpc: '2.0', method: 'initialized', params: {} }),
              JSON.stringify({
                jsonrpc: '2.0',
                id: CODEX_INTERNAL_RESUME_ID,
                method: 'thread/resume',
                params: { threadId: this.codexThreadId, excludeTurns: true },
              }),
            ],
            warmupComplete: false,
          };
        }
        if (!hasMethod && idStr === CODEX_INTERNAL_RESUME_ID) {
          this.codexWarmupStage = 'none';
          return { suppress: true, followUpFrames: [], warmupComplete: true };
        }
        // Suppress startup notifications emitted while internal warmup is still running
        if (hasMethod && !hasId) {
          return { suppress: true, followUpFrames: [], warmupComplete: false };
        }
      }

      if (hasMethod && hasId) {
        this.pendingContainerRequests.add(idStr);
      } else if (!hasMethod && hasId) {
        this.pendingHostRequests.delete(idStr);
        if (typeof obj.result?.thread?.id === 'string' && obj.result.thread.id) {
          this.codexThreadId = obj.result.thread.id;
        }
      } else if (hasMethod && !hasId) {
        if (obj.method === 'thread/started' && typeof obj.params?.thread?.id === 'string') {
          this.codexThreadId = obj.params.thread.id;
        } else if (obj.method === 'turn/started') {
          this.turnActive = true;
        } else if (obj.method === 'turn/completed') {
          this.turnActive = false;
        }
      }
    }

    return { suppress: false, followUpFrames: [], warmupComplete: true };
  }

  public buildResumedRawArgs(originalArgs: string[]): string[] {
    if (this.agentType !== 'claude' || !this.claudeSessionId) {
      return [...originalArgs];
    }
    const cleaned: string[] = [];
    for (let i = 0; i < originalArgs.length; i++) {
      const arg = originalArgs[i];
      if (arg === '--session-id' || arg === '--resume' || arg === '-r') {
        i++; // skip value
        continue;
      }
      if (
        arg.startsWith('--session-id=') ||
        arg.startsWith('--resume=') ||
        arg === '--continue' ||
        arg === '-c'
      ) {
        continue;
      }
      cleaned.push(arg);
    }
    cleaned.push('--resume', this.claudeSessionId);
    return cleaned;
  }

  /**
   * Prepares warmup frames to send immediately to the newly spawned child process after waking.
   * Returns `{ initialFrames, waitForWarmup }` where `waitForWarmup` indicates whether buffered
   * host frames must wait until the warmup handshake completes.
   */
  public prepareResumeWarmup(): { initialFrames: string[]; waitForWarmup: boolean } {
    this.resumedAtLeastOnce = true;
    if (this.agentType === 'claude') {
      this.swallowedClaudeControlIds.clear();
      const frames: string[] = [];
      for (const subtype of CLAUDE_REPLAYABLE_SUBTYPES) {
        const saved = this.claudeControlConfigs.get(subtype);
        if (!saved) continue;
        const syntheticId = `__orca_hib_${subtype}__`;
        this.swallowedClaudeControlIds.add(syntheticId);
        frames.push(
          JSON.stringify({
            type: 'control_request',
            request_id: syntheticId,
            request: saved,
          })
        );
      }
      return { initialFrames: frames, waitForWarmup: frames.length > 0 };
    }

    if (this.agentType === 'codex' && this.codexInitParams && this.codexThreadId) {
      this.codexWarmupStage = 'awaiting_init';
      return {
        initialFrames: [
          JSON.stringify({
            jsonrpc: '2.0',
            id: CODEX_INTERNAL_INIT_ID,
            method: 'initialize',
            params: this.codexInitParams,
          }),
        ],
        waitForWarmup: true,
      };
    }

    return { initialFrames: [], waitForWarmup: false };
  }
}
