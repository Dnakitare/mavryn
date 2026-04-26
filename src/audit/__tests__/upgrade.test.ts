import { describe, it, expect, beforeEach, afterEach } from "vitest";
import Database from "better-sqlite3";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomBytes } from "node:crypto";
import { SqliteAuditStore } from "../store/sqlite.js";
import { computeEventHash } from "../hash.js";

/**
 * End-to-end test for the v0.3.x → v0.5 upgrade path. Constructs a
 * "v0.3.x-shaped" DB on disk (only the migration-001 schema, user_version=0,
 * realistic rows with valid hashes) and opens it with the v0.5 store. The
 * upgrade should be transparent: rows survive, new columns are NULL, the
 * monotonicity watermark is empty, and a subsequent MAC'd write establishes
 * the boundary correctly.
 *
 * This is the test that would have caught a regression where, for example,
 * the migration runner refused to open a DB with user_version=0 and an
 * existing events table.
 */
describe("v0.3.x → v0.5 DB upgrade", () => {
  let tmpDir: string;
  let dbPath: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "mavryn-upgrade-"));
    dbPath = join(tmpDir, "audit.db");
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  function buildV03DbWithRows(): { hashes: string[] } {
    // The exact schema as it shipped in v0.3.x: events table only, no
    // event_mac/anchor_* columns, no audit_meta table, user_version unset
    // (defaults to 0).
    const db = new Database(dbPath);
    db.pragma("journal_mode = WAL");
    db.exec(`
      CREATE TABLE events (
        seq             INTEGER PRIMARY KEY AUTOINCREMENT,
        id              TEXT NOT NULL UNIQUE,
        timestamp       TEXT NOT NULL,
        session_id      TEXT,
        server_name     TEXT,
        agent_id        TEXT,
        tool_name       TEXT NOT NULL,
        tool_arguments  TEXT NOT NULL,
        tool_annotations TEXT,
        policy_decision TEXT NOT NULL DEFAULT 'allow',
        policy_reason   TEXT,
        policies_evaluated TEXT,
        result_status   TEXT,
        result_summary  TEXT,
        result_latency_ms INTEGER,
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
    `);

    const hashes: string[] = [];
    let prev: string | null = null;
    for (let i = 0; i < 3; i++) {
      const id = `legacy-${i}`;
      const timestamp = new Date(2026, 0, i + 1).toISOString();
      const hashable = {
        id,
        timestamp,
        sessionId: "legacy-session",
        serverName: "fs",
        toolName: "read_file",
        toolArguments: { path: `/tmp/${i}` },
        policyDecision: "allow",
        policiesEvaluated: [],
        prevHash: prev,
      };
      const eventHash = computeEventHash(hashable);
      db.prepare(
        `INSERT INTO events (
          id, timestamp, session_id, server_name, tool_name, tool_arguments,
          policy_decision, policies_evaluated, prev_hash, event_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ).run(
        id,
        timestamp,
        "legacy-session",
        "fs",
        "read_file",
        JSON.stringify({ path: `/tmp/${i}` }),
        "allow",
        JSON.stringify([]),
        prev,
        eventHash,
      );
      hashes.push(eventHash);
      prev = eventHash;
    }

    // Sanity: this is what v0.3.x would have left.
    const versionRow = db.pragma("user_version", { simple: true }) as number;
    expect(versionRow).toBe(0);

    db.close();
    return { hashes };
  }

  it("upgrades a v0.3.x DB on first open: rows survive, new columns NULL, audit_meta empty", () => {
    const { hashes } = buildV03DbWithRows();

    // Open with v0.5 store (no key configured).
    const store = new SqliteAuditStore(dbPath);
    try {
      const events = store.getAllEvents();
      expect(events).toHaveLength(3);

      // Pre-existing rows preserved with their hashes.
      expect(events[0].id).toBe("legacy-0");
      expect(events[0].eventHash).toBe(hashes[0]);
      expect(events[2].eventHash).toBe(hashes[2]);

      // New columns exist but are NULL on legacy rows.
      for (const ev of events) {
        expect(ev.eventMac).toBeUndefined();
        expect(ev.anchorHash).toBeUndefined();
        expect(ev.anchorSeq).toBeUndefined();
        expect(ev.anchorSource).toBeUndefined();
      }

      // Watermark empty: no MAC'd writes have happened.
      expect(store.getFirstMacSeq()).toBeNull();
    } finally {
      store.close();
    }

    // user_version is now 2.
    const probe = new Database(dbPath, { readonly: true });
    try {
      expect(probe.pragma("user_version", { simple: true })).toBe(2);
      // audit_meta table exists.
      const tableExists = probe
        .prepare(
          "SELECT name FROM sqlite_master WHERE type='table' AND name='audit_meta'",
        )
        .get();
      expect(tableExists).toBeTruthy();
    } finally {
      probe.close();
    }
  });

  it("appending a MAC'd row to an upgraded DB establishes the watermark at the boundary, not seq=1", () => {
    buildV03DbWithRows();
    const key = randomBytes(32);

    const store = new SqliteAuditStore(dbPath, { macKey: key });
    try {
      const newRow = store.appendAtomic({
        id: "post-upgrade",
        timestamp: new Date(2026, 1, 1).toISOString(),
        sessionId: "new-session",
        serverName: "fs",
        toolName: "write_file",
        toolArguments: { path: "/tmp/new" },
        policyDecision: "allow",
        policiesEvaluated: [],
      });

      expect(newRow.seq).toBe(4); // 3 legacy rows + this one
      expect(newRow.eventMac).toMatch(/^[0-9a-f]{64}$/);
      expect(newRow.prevHash).toBeTruthy(); // chains from row 3

      // Watermark is the new row's seq, NOT 1. Verify monotonicity will
      // correctly classify rows 1-3 as legacy hash-only and require row 4+
      // to be MAC'd.
      expect(store.getFirstMacSeq()).toBe(4);
    } finally {
      store.close();
    }
  });

  it("subsequent MAC'd writes don't move the watermark backward or forward", () => {
    buildV03DbWithRows();
    const key = randomBytes(32);

    const store = new SqliteAuditStore(dbPath, { macKey: key });
    try {
      const first = store.appendAtomic({
        id: "first-maced",
        timestamp: new Date(2026, 1, 1).toISOString(),
        sessionId: "s",
        serverName: "fs",
        toolName: "x",
        toolArguments: {},
        policyDecision: "allow",
        policiesEvaluated: [],
      });
      store.appendAtomic({
        id: "second-maced",
        timestamp: new Date(2026, 1, 2).toISOString(),
        sessionId: "s",
        serverName: "fs",
        toolName: "x",
        toolArguments: {},
        policyDecision: "allow",
        policiesEvaluated: [],
      });
      expect(store.getFirstMacSeq()).toBe(first.seq);
    } finally {
      store.close();
    }
  });

  it("re-opening an upgraded DB does not re-run migrations (user_version stays at 2)", () => {
    buildV03DbWithRows();
    new SqliteAuditStore(dbPath).close();
    // Second open should be a no-op for migrations.
    const store = new SqliteAuditStore(dbPath);
    try {
      // If migrate() re-ran ALTER TABLE here, this open would have thrown
      // "duplicate column event_mac." Reaching this line means the gating
      // worked.
      expect(store.getAllEvents()).toHaveLength(3);
    } finally {
      store.close();
    }
  });
});
