import Database from "better-sqlite3";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import type { AuditEvent } from "../types.js";
import { computeEventHash } from "../hash.js";
import type { AuditStore, EventQuery, AppendEventParams } from "./store.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

export class SqliteAuditStore implements AuditStore {
  private db: Database.Database;

  constructor(dbPath: string) {
    this.db = new Database(dbPath);
    this.db.pragma("journal_mode = WAL");
    this.db.pragma("foreign_keys = ON");
    this.migrate();
  }

  private migrate(): void {
    const possiblePaths = [
      join(__dirname, "migrations", "001.sql"),
      join(__dirname, "..", "src", "audit", "store", "migrations", "001.sql"),
      join(__dirname, "..", "migrations", "001.sql"),
    ];

    let sql: string | undefined;
    for (const p of possiblePaths) {
      try {
        sql = readFileSync(p, "utf-8");
        break;
      } catch {
        continue;
      }
    }

    if (!sql) {
      // Inline fallback migration — kept in sync with migrations/001.sql
      sql = `
        CREATE TABLE IF NOT EXISTS events (
          seq             INTEGER PRIMARY KEY AUTOINCREMENT,
          id              TEXT NOT NULL UNIQUE,
          timestamp       TEXT NOT NULL,
          session_id      TEXT,
          server_name     TEXT,
          agent_id        TEXT,
          tool_name       TEXT NOT NULL,
          tool_arguments  TEXT NOT NULL CHECK(length(tool_arguments) <= 1048576),
          tool_annotations TEXT,
          policy_decision TEXT NOT NULL DEFAULT 'allow',
          policy_reason   TEXT,
          policies_evaluated TEXT,
          result_status   TEXT CHECK(result_status IN ('success', 'error', 'blocked') OR result_status IS NULL),
          result_summary  TEXT,
          result_latency_ms INTEGER CHECK(result_latency_ms >= 0 OR result_latency_ms IS NULL),
          user_id         TEXT,
          source_tag      TEXT,
          prompt_context  TEXT,
          turn_id         TEXT,
          assistant_message TEXT,
          system_prompt_hash TEXT,
          meta            TEXT,
          prev_hash       TEXT UNIQUE,
          event_hash      TEXT NOT NULL UNIQUE,
          created_at      TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
        CREATE INDEX IF NOT EXISTS idx_events_decision ON events(policy_decision);
        CREATE INDEX IF NOT EXISTS idx_events_source ON events(source_tag);
        CREATE INDEX IF NOT EXISTS idx_events_turn ON events(turn_id);
        CREATE INDEX IF NOT EXISTS idx_events_tool_time ON events(tool_name, timestamp);
        CREATE INDEX IF NOT EXISTS idx_events_server_time ON events(server_name, timestamp);
        CREATE INDEX IF NOT EXISTS idx_events_user_time ON events(user_id, timestamp);
      `;
    }

    this.db.exec(sql);
  }

  append(event: AuditEvent): void {
    const stmt = this.db.prepare(`
      INSERT INTO events (
        id, timestamp, session_id, server_name, agent_id,
        tool_name, tool_arguments, tool_annotations,
        policy_decision, policy_reason, policies_evaluated,
        result_status, result_summary, result_latency_ms,
        user_id, source_tag, prompt_context,
        turn_id, assistant_message, system_prompt_hash, meta,
        prev_hash, event_hash
      ) VALUES (
        @id, @timestamp, @sessionId, @serverName, @agentId,
        @toolName, @toolArguments, @toolAnnotations,
        @policyDecision, @policyReason, @policiesEvaluated,
        @resultStatus, @resultSummary, @resultLatencyMs,
        @userId, @sourceTag, @promptContext,
        @turnId, @assistantMessage, @systemPromptHash, @meta,
        @prevHash, @eventHash
      )
    `);

    stmt.run({
      id: event.id,
      timestamp: event.timestamp,
      sessionId: event.sessionId,
      serverName: event.serverName,
      agentId: event.agentId ?? null,
      toolName: event.toolName,
      toolArguments: JSON.stringify(event.toolArguments),
      toolAnnotations: event.toolAnnotations ? JSON.stringify(event.toolAnnotations) : null,
      policyDecision: event.policyDecision,
      policyReason: event.policyReason ?? null,
      policiesEvaluated: JSON.stringify(event.policiesEvaluated),
      resultStatus: event.resultStatus ?? null,
      resultSummary: event.resultSummary ?? null,
      resultLatencyMs: event.resultLatencyMs ?? null,
      userId: event.userId ?? null,
      sourceTag: event.sourceTag ?? null,
      promptContext: event.promptContext ?? null,
      turnId: event.turnId ?? null,
      assistantMessage: event.assistantMessage ?? null,
      systemPromptHash: event.systemPromptHash ?? null,
      meta: event.meta ? JSON.stringify(event.meta) : null,
      prevHash: event.prevHash,
      eventHash: event.eventHash,
    });
  }

  appendAtomic(params: AppendEventParams): AuditEvent {
    const insertStmt = this.db.prepare(`
      INSERT INTO events (
        id, timestamp, session_id, server_name, agent_id,
        tool_name, tool_arguments, tool_annotations,
        policy_decision, policy_reason, policies_evaluated,
        result_status, result_summary, result_latency_ms,
        user_id, source_tag, prompt_context,
        turn_id, assistant_message, system_prompt_hash, meta,
        prev_hash, event_hash
      ) VALUES (
        @id, @timestamp, @sessionId, @serverName, @agentId,
        @toolName, @toolArguments, @toolAnnotations,
        @policyDecision, @policyReason, @policiesEvaluated,
        @resultStatus, @resultSummary, @resultLatencyMs,
        @userId, @sourceTag, @promptContext,
        @turnId, @assistantMessage, @systemPromptHash, @meta,
        @prevHash, @eventHash
      )
    `);

    const latestHashStmt = this.db.prepare(
      "SELECT event_hash FROM events ORDER BY seq DESC LIMIT 1",
    );

    // BEGIN IMMEDIATE acquires the write lock at transaction start, so the
    // SELECT for prevHash and the INSERT can't be interleaved by another
    // process. Without this the chain can fork under concurrent writers.
    const trx = this.db.transaction(() => {
      const row = latestHashStmt.get() as any;
      const prevHash: string | null = row?.event_hash ?? null;

      const hashableEvent = {
        id: params.id,
        timestamp: params.timestamp,
        sessionId: params.sessionId,
        serverName: params.serverName,
        agentId: params.agentId,
        toolName: params.toolName,
        toolArguments: params.toolArguments,
        toolAnnotations: params.toolAnnotations,
        policyDecision: params.policyDecision,
        policiesEvaluated: params.policiesEvaluated,
        resultStatus: params.resultStatus,
        userId: params.userId,
        sourceTag: params.sourceTag,
        promptContext: params.promptContext,
        turnId: params.turnId,
        assistantMessage: params.assistantMessage,
        systemPromptHash: params.systemPromptHash,
        meta: params.meta,
        prevHash,
      };

      const eventHash = computeEventHash(hashableEvent);

      const event: AuditEvent = {
        id: params.id,
        timestamp: params.timestamp,
        sessionId: params.sessionId,
        serverName: params.serverName,
        agentId: params.agentId,
        toolName: params.toolName,
        toolArguments: params.toolArguments,
        toolAnnotations: params.toolAnnotations,
        policyDecision: params.policyDecision as AuditEvent["policyDecision"],
        policyReason: params.policyReason,
        policiesEvaluated: params.policiesEvaluated,
        resultStatus: params.resultStatus,
        resultSummary: params.resultSummary,
        resultLatencyMs: params.resultLatencyMs,
        userId: params.userId,
        sourceTag: params.sourceTag,
        promptContext: params.promptContext,
        turnId: params.turnId,
        assistantMessage: params.assistantMessage,
        systemPromptHash: params.systemPromptHash,
        meta: params.meta,
        prevHash,
        eventHash,
      };

      const runResult = insertStmt.run({
        id: event.id,
        timestamp: event.timestamp,
        sessionId: event.sessionId,
        serverName: event.serverName,
        agentId: event.agentId ?? null,
        toolName: event.toolName,
        toolArguments: JSON.stringify(event.toolArguments),
        toolAnnotations: event.toolAnnotations ? JSON.stringify(event.toolAnnotations) : null,
        policyDecision: event.policyDecision,
        policyReason: event.policyReason ?? null,
        policiesEvaluated: JSON.stringify(event.policiesEvaluated),
        resultStatus: event.resultStatus ?? null,
        resultSummary: event.resultSummary ?? null,
        resultLatencyMs: event.resultLatencyMs ?? null,
        userId: event.userId ?? null,
        sourceTag: event.sourceTag ?? null,
        promptContext: event.promptContext ?? null,
        turnId: event.turnId ?? null,
        assistantMessage: event.assistantMessage ?? null,
        systemPromptHash: event.systemPromptHash ?? null,
        meta: event.meta ? JSON.stringify(event.meta) : null,
        prevHash: event.prevHash,
        eventHash: event.eventHash,
      });

      event.seq = Number(runResult.lastInsertRowid);
      return event;
    });

    return trx.immediate();
  }

  query(filter: EventQuery): AuditEvent[] {
    const conditions: string[] = [];
    const params: Record<string, unknown> = {};

    if (filter.sessionId) {
      conditions.push("session_id = @sessionId");
      params.sessionId = filter.sessionId;
    }
    if (filter.serverName) {
      conditions.push("server_name = @serverName");
      params.serverName = filter.serverName;
    }
    if (filter.toolName) {
      conditions.push("tool_name = @toolName");
      params.toolName = filter.toolName;
    }
    if (filter.policyDecision) {
      conditions.push("policy_decision = @policyDecision");
      params.policyDecision = filter.policyDecision;
    }
    if (filter.resultStatus) {
      conditions.push("result_status = @resultStatus");
      params.resultStatus = filter.resultStatus;
    }
    if (filter.userId) {
      conditions.push("user_id = @userId");
      params.userId = filter.userId;
    }
    if (filter.sourceTag) {
      conditions.push("source_tag = @sourceTag");
      params.sourceTag = filter.sourceTag;
    }
    if (filter.turnId) {
      conditions.push("turn_id = @turnId");
      params.turnId = filter.turnId;
    }
    if (filter.fromTimestamp) {
      conditions.push("timestamp >= @fromTimestamp");
      params.fromTimestamp = filter.fromTimestamp;
    }
    if (filter.toTimestamp) {
      conditions.push("timestamp <= @toTimestamp");
      params.toTimestamp = filter.toTimestamp;
    }

    const where = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";
    const limit = filter.limit ?? 100;
    const offset = filter.offset ?? 0;

    const rows = this.db
      .prepare(`SELECT * FROM events ${where} ORDER BY timestamp DESC, seq DESC LIMIT @limit OFFSET @offset`)
      .all({ ...params, limit, offset }) as any[];

    return rows.map(this.rowToEvent);
  }

  getLatestHash(): string | null {
    const row = this.db
      .prepare("SELECT event_hash FROM events ORDER BY seq DESC LIMIT 1")
      .get() as any;
    return row?.event_hash ?? null;
  }

  getEventCount(): number {
    const row = this.db.prepare("SELECT COUNT(*) as count FROM events").get() as any;
    return row.count;
  }

  getAllEvents(limit = 1000, offset = 0): AuditEvent[] {
    const rows = this.db
      .prepare("SELECT * FROM events ORDER BY seq ASC LIMIT ? OFFSET ?")
      .all(limit, offset) as any[];
    return rows.map(this.rowToEvent);
  }

  *iterateAllEvents(): IterableIterator<AuditEvent> {
    const stmt = this.db.prepare("SELECT * FROM events ORDER BY seq ASC");
    for (const row of stmt.iterate() as IterableIterator<any>) {
      yield this.rowToEvent(row);
    }
  }

  getSessionIds(): string[] {
    const rows = this.db
      .prepare(
        "SELECT session_id FROM events WHERE session_id IS NOT NULL GROUP BY session_id ORDER BY MIN(timestamp) DESC",
      )
      .all() as any[];
    return rows.map((r) => r.session_id);
  }

  close(): void {
    this.db.close();
  }

  private rowToEvent(row: any): AuditEvent {
    return {
      seq: row.seq,
      id: row.id,
      timestamp: row.timestamp,
      sessionId: row.session_id,
      serverName: row.server_name,
      agentId: row.agent_id ?? undefined,
      toolName: row.tool_name,
      toolArguments: JSON.parse(row.tool_arguments),
      toolAnnotations: row.tool_annotations ? JSON.parse(row.tool_annotations) : undefined,
      policyDecision: row.policy_decision,
      policyReason: row.policy_reason ?? undefined,
      policiesEvaluated: row.policies_evaluated ? JSON.parse(row.policies_evaluated) : [],
      resultStatus: row.result_status ?? undefined,
      resultSummary: row.result_summary ?? undefined,
      resultLatencyMs: row.result_latency_ms ?? undefined,
      userId: row.user_id ?? undefined,
      sourceTag: row.source_tag ?? undefined,
      promptContext: row.prompt_context ?? undefined,
      turnId: row.turn_id ?? undefined,
      assistantMessage: row.assistant_message ?? undefined,
      systemPromptHash: row.system_prompt_hash ?? undefined,
      meta: row.meta ? JSON.parse(row.meta) : undefined,
      prevHash: row.prev_hash,
      eventHash: row.event_hash,
    };
  }
}
