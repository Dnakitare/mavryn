import type { AuditEvent } from "../types.js";

export interface EventQuery {
  sessionId?: string;
  serverName?: string;
  toolName?: string;
  policyDecision?: string;
  resultStatus?: string;
  userId?: string;
  sourceTag?: string;
  turnId?: string;
  fromTimestamp?: string;
  toTimestamp?: string;
  limit?: number;
  offset?: number;
}

/** Params for atomic append — the store computes prevHash inside a transaction. */
export interface AppendEventParams {
  id: string;
  timestamp: string;
  sessionId: string;
  serverName: string;
  agentId?: string;
  toolName: string;
  toolArguments: Record<string, unknown>;
  toolAnnotations?: Record<string, unknown>;
  policyDecision: string;
  policyReason?: string;
  policiesEvaluated: string[];
  resultStatus?: "success" | "error" | "blocked";
  resultSummary?: string;
  resultLatencyMs?: number;
  userId?: string;
  sourceTag?: string;
  promptContext?: string;
  turnId?: string;
  assistantMessage?: string;
  systemPromptHash?: string;
  meta?: Record<string, unknown>;
  redactionsApplied?: boolean;
}

export interface AuditStore {
  append(event: AuditEvent): void;
  /** Atomically reads prevHash, computes event hash, and inserts. Returns the complete event. */
  appendAtomic(params: AppendEventParams): AuditEvent;
  query(filter: EventQuery): AuditEvent[];
  getLatestHash(): string | null;
  getEventCount(): number;
  getAllEvents(limit?: number, offset?: number): AuditEvent[];
  /** Lazy seq-ordered iterator. Use for verify/export at any DB size — memory stays constant. */
  iterateAllEvents(): IterableIterator<AuditEvent>;
  getSessionIds(): string[];
  close(): void;
}
