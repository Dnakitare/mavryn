import Database from "better-sqlite3";
import type { AuditEvent } from "../types.js";
import { computeEventHash, computeEventMac } from "../hash.js";
import type { AuditStore, EventQuery, AppendEventParams } from "./store.js";

const SCHEMA_VERSION = 2;

// Migrations are inline (single source of truth). Numbered identifiers run
// in ascending order; user_version pins which have applied. Each migration
// is idempotent within its slot — once user_version progresses past it, it
// never runs again.

const MIGRATION_001 = `
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
    redactions_applied INTEGER NOT NULL DEFAULT 0,
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

// v0.5: keyed-MAC chain authenticity + pre-shaped anchor columns + audit_meta
// watermark for monotonicity. ADD COLUMN is not idempotent — only safe
// because user_version gates entry to this block.
const MIGRATION_002 = `
  ALTER TABLE events ADD COLUMN event_mac TEXT;
  ALTER TABLE events ADD COLUMN anchor_hash TEXT;
  ALTER TABLE events ADD COLUMN anchor_seq INTEGER;
  ALTER TABLE events ADD COLUMN anchor_source TEXT;
  CREATE TABLE IF NOT EXISTS audit_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );
`;

const META_FIRST_MAC_SEQ = "first_mac_seq";

export class SqliteAuditStore implements AuditStore {
  private db: Database.Database;
  private macKey: Buffer | null;

  constructor(dbPath: string, opts?: { macKey?: Buffer | null }) {
    this.db = new Database(dbPath);
    this.db.pragma("journal_mode = WAL");
    this.db.pragma("foreign_keys = ON");
    this.macKey = opts?.macKey ?? null;
    this.migrate();
  }

  private migrate(): void {
    const versionAtOpen = this.db.pragma("user_version", { simple: true }) as number;

    if (versionAtOpen > SCHEMA_VERSION) {
      throw new Error(
        `audit DB user_version=${versionAtOpen} but this build only knows up to ${SCHEMA_VERSION}. ` +
          `This build cannot read columns added in a newer schema version. ` +
          `Upgrade Mavryn, or restore from a v${SCHEMA_VERSION}-compatible backup.`,
      );
    }

    if (versionAtOpen >= SCHEMA_VERSION) return;

    // Wrap the entire migration sequence in one transaction so a partial
    // failure (disk full, read-only FS on the second ALTER, etc.) rolls back
    // cleanly. Without this, user_version could stay at N while some columns
    // for N+1 already exist — next open would re-run the migration and the
    // ALTER would fail "duplicate column," requiring manual SQL repair.
    const runMigrations = this.db.transaction(() => {
      let v = versionAtOpen;
      if (v < 1) {
        this.db.exec(MIGRATION_001);
        this.db.pragma("user_version = 1");
        v = 1;
      }
      if (v < 2) {
        this.db.exec(MIGRATION_002);
        this.db.pragma("user_version = 2");
        v = 2;
      }
    });
    runMigrations();
  }

  append(event: AuditEvent): void {
    // Guardrail: append() doesn't compute MACs (caller-supplied). When the
    // store is configured with a key, accepting a row that lacks a MAC would
    // create an attestation gap a verifier-with-key would later flag. Force
    // callers (currently only tests; potentially future importers) to be
    // explicit. Use appendAtomic for the normal write path — it computes both.
    if (this.macKey && !event.eventMac) {
      throw new Error(
        "SqliteAuditStore.append: store is configured with a macKey but the event has no eventMac. " +
          "Use appendAtomic for normal writes (computes hash + MAC), or set event.eventMac explicitly.",
      );
    }

    const stmt = this.db.prepare(`
      INSERT INTO events (
        id, timestamp, session_id, server_name, agent_id,
        tool_name, tool_arguments, tool_annotations,
        policy_decision, policy_reason, policies_evaluated,
        result_status, result_summary, result_latency_ms,
        user_id, source_tag, prompt_context,
        turn_id, assistant_message, system_prompt_hash, meta,
        redactions_applied,
        prev_hash, event_hash, event_mac
      ) VALUES (
        @id, @timestamp, @sessionId, @serverName, @agentId,
        @toolName, @toolArguments, @toolAnnotations,
        @policyDecision, @policyReason, @policiesEvaluated,
        @resultStatus, @resultSummary, @resultLatencyMs,
        @userId, @sourceTag, @promptContext,
        @turnId, @assistantMessage, @systemPromptHash, @meta,
        @redactionsApplied,
        @prevHash, @eventHash, @eventMac
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
      redactionsApplied: event.redactionsApplied ? 1 : 0,
      prevHash: event.prevHash,
      eventHash: event.eventHash,
      eventMac: event.eventMac ?? null,
    });
  }

  /** True if this store is configured with a MAC key. Used by callers (e.g. CLI verify) to decide policy. */
  hasMacKey(): boolean {
    return this.macKey !== null;
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
        redactions_applied,
        prev_hash, event_hash, event_mac
      ) VALUES (
        @id, @timestamp, @sessionId, @serverName, @agentId,
        @toolName, @toolArguments, @toolAnnotations,
        @policyDecision, @policyReason, @policiesEvaluated,
        @resultStatus, @resultSummary, @resultLatencyMs,
        @userId, @sourceTag, @promptContext,
        @turnId, @assistantMessage, @systemPromptHash, @meta,
        @redactionsApplied,
        @prevHash, @eventHash, @eventMac
      )
    `);

    const latestHashStmt = this.db.prepare(
      "SELECT event_hash FROM events ORDER BY seq DESC LIMIT 1",
    );

    // INSERT OR IGNORE keeps the watermark stable after the first MAC'd write
    // (cost: one B-tree lookup per write — negligible vs. the canonicalize +
    // INSERT we already do).
    const setFirstMacSeqStmt = this.db.prepare(
      `INSERT OR IGNORE INTO audit_meta (key, value) VALUES ('${META_FIRST_MAC_SEQ}', @seq)`,
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
        redactionsApplied: params.redactionsApplied,
        prevHash,
      };

      const eventHash = computeEventHash(hashableEvent);
      const eventMac = this.macKey ? computeEventMac(hashableEvent, this.macKey) : undefined;

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
        redactionsApplied: params.redactionsApplied,
        prevHash,
        eventHash,
        eventMac,
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
        redactionsApplied: event.redactionsApplied ? 1 : 0,
        prevHash: event.prevHash,
        eventHash: event.eventHash,
        eventMac: event.eventMac ?? null,
      });

      event.seq = Number(runResult.lastInsertRowid);

      // Record the watermark on the FIRST MAC'd write. Same transaction as
      // the INSERT, so an attacker can't observe a row-without-watermark
      // intermediate state. INSERT OR IGNORE is a no-op on subsequent writes.
      if (eventMac) {
        setFirstMacSeqStmt.run({ seq: String(event.seq) });
      }

      return event;
    });

    return trx.immediate();
  }

  /** Read a singleton value from audit_meta, or null. */
  getMeta(key: string): string | null {
    const row = this.db
      .prepare("SELECT value FROM audit_meta WHERE key = ?")
      .get(key) as { value: string } | undefined;
    return row?.value ?? null;
  }

  /** seq of the first row ever written under a configured macKey, or null if no MAC'd rows yet. */
  getFirstMacSeq(): number | null {
    const v = this.getMeta(META_FIRST_MAC_SEQ);
    if (v === null) return null;
    const n = Number(v);
    return Number.isFinite(n) ? n : null;
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
      redactionsApplied: row.redactions_applied === 1,
      prevHash: row.prev_hash,
      eventHash: row.event_hash,
      eventMac: row.event_mac ?? undefined,
      anchorHash: row.anchor_hash ?? undefined,
      anchorSeq: row.anchor_seq ?? undefined,
      anchorSource: row.anchor_source ?? undefined,
    };
  }
}
