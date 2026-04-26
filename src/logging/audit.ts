import { mkdirSync } from "fs";
import path from "path";
import type { Logger } from "./logger.js";
import { redactString, redactValue } from "../security/redact.js";
import { SqliteAuditStore } from "../audit/store/index.js";

/**
 * Audit adapter — preserves the toolCall/toolDenied API surface used by
 * MavrynServer and routes to the hash-chained SQLite store. Tool-call rows
 * are tamper-evident; integrity is verifiable via `mavryn audit verify`.
 *
 * Errors during write never crash the server. On the first failure we log
 * once and disable further writes to avoid log spam.
 */
export class AuditLog {
  private store: SqliteAuditStore | null = null;
  private dbPath: string;
  private enabled: boolean;
  private writeable = true;
  private initialized = false;
  private sessionId: string;
  private agentId: string | undefined;
  private logger: Logger;

  constructor(
    enabled: boolean,
    dbPath: string,
    logger: Logger,
    sessionId?: string,
    agentId?: string,
  ) {
    this.enabled = enabled;
    this.dbPath = dbPath;
    this.logger = logger;
    this.sessionId = sessionId ?? crypto.randomUUID();
    this.agentId = agentId;
  }

  private ensureStore(): SqliteAuditStore | null {
    if (!this.enabled || !this.writeable) return null;
    if (this.initialized) return this.store;

    try {
      mkdirSync(path.dirname(this.dbPath), { recursive: true });
      this.store = new SqliteAuditStore(this.dbPath);
      this.initialized = true;
      return this.store;
    } catch (err) {
      this.logger.error("audit_open_failed", {
        path: this.dbPath,
        error: err instanceof Error ? err.message : String(err),
      });
      this.writeable = false;
      this.initialized = true;
      return null;
    }
  }

  /**
   * Eagerly open the store. Called at server startup so a broken audit log
   * is surfaced immediately rather than on the first tool call. Combined
   * with audit.failClosed, this lets the server refuse to start (or start
   * but deny tool calls) if the audit is non-functional.
   */
  init(): void {
    if (!this.enabled) return;
    this.ensureStore();
  }

  /**
   * True iff audit is disabled OR audit is enabled and writes are succeeding.
   * Used by MavrynServer to gate tool calls when audit.failClosed is on.
   */
  isHealthy(): boolean {
    return !this.enabled || this.writeable;
  }

  private writeAppend(params: {
    serverName: string;
    toolName: string;
    toolArguments: Record<string, unknown>;
    policyDecision: "allow" | "deny";
    policyReason?: string;
    policiesEvaluated?: string[];
    resultStatus?: "success" | "error" | "blocked";
    resultSummary?: string;
    resultLatencyMs?: number;
  }): void {
    const store = this.ensureStore();
    if (!store) return;

    try {
      store.appendAtomic({
        id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        sessionId: this.sessionId,
        agentId: this.agentId,
        serverName: params.serverName,
        toolName: params.toolName,
        toolArguments: redactValue(params.toolArguments) as Record<string, unknown>,
        policyDecision: params.policyDecision,
        policyReason: params.policyReason,
        policiesEvaluated: params.policiesEvaluated ?? [],
        resultStatus: params.resultStatus,
        resultSummary: params.resultSummary ? redactString(params.resultSummary) : undefined,
        resultLatencyMs: params.resultLatencyMs,
      });
    } catch (err) {
      if (this.writeable) {
        this.logger.error("audit_write_failed", {
          path: this.dbPath,
          error: err instanceof Error ? err.message : String(err),
        });
        this.writeable = false;
      }
    }
  }

  toolCall(data: {
    upstream: string;
    tool: string;
    namespacedTool: string;
    args: Record<string, unknown>;
    success: boolean;
    latencyMs: number;
    error?: string;
    policiesEvaluated?: string[];
  }): void {
    this.writeAppend({
      serverName: data.upstream,
      toolName: data.tool,
      toolArguments: data.args,
      policyDecision: "allow",
      policiesEvaluated: data.policiesEvaluated,
      resultStatus: data.success ? "success" : "error",
      resultSummary: data.error,
      resultLatencyMs: data.latencyMs,
    });
  }

  toolDenied(data: {
    upstream: string;
    tool: string;
    namespacedTool: string;
    args: Record<string, unknown>;
    reason: string;
    policiesEvaluated?: string[];
  }): void {
    this.writeAppend({
      serverName: data.upstream,
      toolName: data.tool,
      toolArguments: data.args,
      policyDecision: "deny",
      policyReason: data.reason,
      policiesEvaluated: data.policiesEvaluated,
      resultStatus: "blocked",
    });
  }

  close(): void {
    this.store?.close();
    this.store = null;
    this.initialized = false;
  }
}
