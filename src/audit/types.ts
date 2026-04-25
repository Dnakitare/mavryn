export type PolicyDecisionType = 'allow' | 'deny' | 'escalate';

export interface AuditEvent {
  /** Monotonic insertion sequence assigned by SQLite. The chain is ordered by seq, not timestamp. Read-only. */
  seq?: number;
  id: string;
  timestamp: string;
  sessionId: string;
  serverName: string;
  agentId?: string;
  toolName: string;
  toolArguments: Record<string, unknown>;
  toolAnnotations?: Record<string, unknown>;
  policyDecision: PolicyDecisionType;
  policyReason?: string;
  policiesEvaluated: string[];
  resultStatus?: 'success' | 'error' | 'blocked';
  resultSummary?: string;
  resultLatencyMs?: number;
  /** Human user that triggered the call (Sam — for per-engineer attribution in shared agents). */
  userId?: string;
  /** Free-form grouping label (Nadia — for fleet/agent identification across multiple sources). */
  sourceTag?: string;
  /** Natural-language context that led to this tool call, when the agent provides it. */
  promptContext?: string;
  /** Correlates tool calls within a single LLM turn. Populated by @mavryn/audit-sdk; null in pure-proxy mode. */
  turnId?: string;
  /** The LLM assistant message that decided to make this tool call (redacted). Populated by SDK. */
  assistantMessage?: string;
  /** Hash of the system prompt active at the time of the call. Populated by SDK. */
  systemPromptHash?: string;
  /** Free-form structured metadata passed via MCP `_meta`. Catch-all for SDK or client-side context. */
  meta?: Record<string, unknown>;
  prevHash: string | null;
  eventHash: string;
}
