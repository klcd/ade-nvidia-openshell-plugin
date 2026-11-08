/**
 * Strongly-typed definitions for OpenShell Landlock sandboxes,
 * Orca Chat UI protocols, and agent lifecycle bridges.
 */

export type AgentType = 'claude' | 'codex' | 'agy';

// -----------------------------------------------------------------------------
// OpenShell Policy Schemas
// -----------------------------------------------------------------------------

export interface LandlockPolicy {
  compatibility: 'best_effort' | 'hard_requirement';
}

export interface FilesystemPolicy {
  include_workdir?: boolean;
  read_only: string[];
  read_write: string[];
}

export interface ProcessPolicy {
  run_as_user?: string;
  run_as_group?: string;
}

export interface NetworkEndpoint {
  host: string;
  port: number;
  protocol?: 'rest' | 'tcp' | 'grpc';
  access?: 'read-write' | 'read-only';
  enforcement?: 'enforce' | 'audit';
  request_body_credential_rewrite?: boolean;
}

export interface NetworkPolicy {
  name?: string;
  endpoints: NetworkEndpoint[];
}

export interface NetworkMiddleware {
  name?: string;
  middleware: string;
  order?: number;
  config?: Record<string, unknown>;
  on_error?: 'fail_closed' | 'fail_open';
  endpoints: { include?: string[]; exclude?: string[] };
}

export interface OpenShellPolicy {
  version: number;
  filesystem_policy?: FilesystemPolicy;
  landlock?: LandlockPolicy;
  process?: ProcessPolicy;
  network_policies?: Record<string, NetworkPolicy>;
  network_middlewares?: Record<string, NetworkMiddleware>;
}

// -----------------------------------------------------------------------------
// JSON-RPC 2.0 (Orca Chat Mode & Codex app-server protocol)
// -----------------------------------------------------------------------------

export interface JsonRpcRequest<T = unknown> {
  jsonrpc: '2.0';
  id: string | number;
  method: string;
  params?: T;
}

export interface JsonRpcResponse<T = unknown> {
  jsonrpc: '2.0';
  id: string | number;
  result?: T;
  error?: {
    code: number;
    message: string;
    data?: unknown;
  };
}

export interface JsonRpcNotification<T = unknown> {
  jsonrpc: '2.0';
  method: string;
  params?: T;
}

export type JsonRpcMessage = JsonRpcRequest | JsonRpcResponse | JsonRpcNotification;

// -----------------------------------------------------------------------------
// Agent Adapter Interface
// -----------------------------------------------------------------------------

export interface AgentAdapter {
  readonly type: AgentType;
  readonly binaryName: string;
  readonly containerImage: string;
  readonly providerName: string;

  /**
   * Fast-path check: returns true if the request should bypass the container
   * (e.g. --version, --help, Orca model discovery probes).
   */
  shouldBypassSandbox(args: string[], cwd: string): boolean;

  /**
   * Extract credentials from host keychain or environment without user prompts.
   */
  getCredentials(): Promise<Record<string, string>>;

  /**
   * Stage configuration, workspace trust, and telemetry opt-outs in stageDir.
   */
  stageConfiguration(stageDir: string, projectRoot: string, projectName: string): Promise<void>;

  /**
   * Build the execution command array for `openshell sandbox exec`.
   */
  buildExecArgs(
    sandboxName: string,
    projectName: string,
    args: string[],
    credentials: Record<string, string>
  ): string[];

  /**
   * Synchronize files back to the host filesystem on session exit.
   */
  syncBack(
    sandboxName: string,
    projectRoot: string,
    projectName: string,
    workspaceWritePaths?: string[] | null
  ): Promise<void>;
}
