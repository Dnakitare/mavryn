import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { computeEventHash, computeEventMac, safeHexEqual, verifyChain } from "../hash.js";
import { SqliteAuditStore } from "../store/sqlite.js";
import type { HashableEvent } from "../hash.js";
import type { AuditEvent } from "../types.js";

function baseEvent(overrides: Partial<HashableEvent> = {}): HashableEvent {
  return {
    id: "evt-1",
    timestamp: "2026-04-26T12:00:00.000Z",
    sessionId: "sess-1",
    serverName: "test-server",
    toolName: "read_file",
    toolArguments: { path: "/tmp/x" },
    policyDecision: "allow",
    prevHash: null,
    ...overrides,
  };
}

describe("safeHexEqual", () => {
  it("returns true for equal hex strings", () => {
    expect(safeHexEqual("deadbeef", "deadbeef")).toBe(true);
  });
  it("returns false for different hex strings of same length", () => {
    expect(safeHexEqual("deadbeef", "cafebabe")).toBe(false);
  });
  it("returns false for different-length inputs", () => {
    expect(safeHexEqual("deadbeef", "deadbe")).toBe(false);
  });
  it("returns false for empty inputs", () => {
    expect(safeHexEqual("", "")).toBe(false);
  });
  it("returns false for non-hex inputs", () => {
    // Buffer.from('zz', 'hex') silently returns empty — make sure we don't accidentally pass empty==empty
    expect(safeHexEqual("zzzz", "zzzz")).toBe(false);
  });
});

describe("computeEventMac", () => {
  const key = randomBytes(32);

  it("is deterministic for same input + key", () => {
    const ev = baseEvent();
    expect(computeEventMac(ev, key)).toBe(computeEventMac(ev, key));
  });

  it("differs across keys for same input", () => {
    const otherKey = randomBytes(32);
    const ev = baseEvent();
    expect(computeEventMac(ev, key)).not.toBe(computeEventMac(ev, otherKey));
  });

  it("differs from event_hash even when keyed with empty-ish material would not", () => {
    // event_hash and event_mac share canonical input but differ in primitive
    const ev = baseEvent();
    expect(computeEventMac(ev, key)).not.toBe(computeEventHash(ev));
  });

  it("rejects empty keys", () => {
    expect(() => computeEventMac(baseEvent(), Buffer.alloc(0))).toThrow();
  });

  it("changes when any field changes", () => {
    const ev1 = baseEvent({ toolArguments: { path: "/a" } });
    const ev2 = baseEvent({ toolArguments: { path: "/b" } });
    expect(computeEventMac(ev1, key)).not.toBe(computeEventMac(ev2, key));
  });
});

describe("verifyChain with key", () => {
  const key = randomBytes(32);

  function chain(n: number, withMac: boolean): AuditEvent[] {
    const events: AuditEvent[] = [];
    let prev: string | null = null;
    for (let i = 0; i < n; i++) {
      const h: HashableEvent = baseEvent({ id: `evt-${i}`, prevHash: prev });
      const eventHash = computeEventHash(h);
      const event: AuditEvent = {
        ...h,
        policiesEvaluated: [],
        eventHash,
        eventMac: withMac ? computeEventMac(h, key) : undefined,
      } as AuditEvent;
      events.push(event);
      prev = eventHash;
    }
    return events;
  }

  it("accepts a valid MACed chain when key matches", () => {
    expect(verifyChain(chain(3, true), { key }).valid).toBe(true);
  });

  it("rejects a MACed chain when key is wrong", () => {
    const wrongKey = randomBytes(32);
    const result = verifyChain(chain(3, true), { key: wrongKey });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("event_mac mismatch");
  });

  it("accepts a hash-only chain regardless of whether a key is supplied", () => {
    const events = chain(3, false);
    expect(verifyChain(events, { key }).valid).toBe(true);
    expect(verifyChain(events).valid).toBe(true);
  });

  it("detects tampering via MAC even when hash is recomputed", () => {
    const events = chain(3, true);
    // Simulate a malicious operator: modify content, recompute event_hash and
    // forward chain. They have no key, so event_mac stays stale.
    events[1].toolArguments = { path: "/evil" };
    events[1].eventHash = computeEventHash(events[1]);
    events[2].prevHash = events[1].eventHash;
    events[2].eventHash = computeEventHash(events[2]);

    // Without key: hashes look fine, attack succeeds.
    expect(verifyChain(events).valid).toBe(true);
    // With key: MAC mismatch on row 1.
    const result = verifyChain(events, { key });
    expect(result.valid).toBe(false);
    expect(result.brokenAt).toBe(1);
    expect(result.reason).toBe("event_mac mismatch");
  });
});

describe("SqliteAuditStore with macKey", () => {
  const key = randomBytes(32);
  let tmpDir: string;
  let dbPath: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "mavryn-mac-"));
    dbPath = join(tmpDir, "test.db");
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("populates event_mac when key is configured", () => {
    const store = new SqliteAuditStore(dbPath, { macKey: key });
    try {
      const event = store.appendAtomic({
        id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        sessionId: "s",
        serverName: "test",
        toolName: "read",
        toolArguments: {},
        policyDecision: "allow",
        policiesEvaluated: [],
      });
      expect(event.eventMac).toBeDefined();
      expect(event.eventMac).toMatch(/^[0-9a-f]{64}$/);

      const retrieved = store.getAllEvents()[0];
      expect(retrieved.eventMac).toBe(event.eventMac);
    } finally {
      store.close();
    }
  });

  it("leaves event_mac NULL when no key is configured", () => {
    const store = new SqliteAuditStore(dbPath);
    try {
      store.appendAtomic({
        id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        sessionId: "s",
        serverName: "test",
        toolName: "read",
        toolArguments: {},
        policyDecision: "allow",
        policiesEvaluated: [],
      });
      const retrieved = store.getAllEvents()[0];
      expect(retrieved.eventMac).toBeUndefined();
    } finally {
      store.close();
    }
  });

  it("supports mixed DB: rows written before key was enabled stay hash-only; new rows are MACed", () => {
    // Phase 1: no key
    let store = new SqliteAuditStore(dbPath);
    for (let i = 0; i < 2; i++) {
      store.appendAtomic({
        id: crypto.randomUUID(),
        timestamp: new Date(2026, 0, i + 1).toISOString(),
        sessionId: "s",
        serverName: "test",
        toolName: "read",
        toolArguments: { i },
        policyDecision: "allow",
        policiesEvaluated: [],
      });
    }
    store.close();

    // Phase 2: key turned on
    store = new SqliteAuditStore(dbPath, { macKey: key });
    for (let i = 0; i < 2; i++) {
      store.appendAtomic({
        id: crypto.randomUUID(),
        timestamp: new Date(2026, 1, i + 1).toISOString(),
        sessionId: "s",
        serverName: "test",
        toolName: "read",
        toolArguments: { i: i + 100 },
        policyDecision: "allow",
        policiesEvaluated: [],
      });
    }

    try {
      const events = store.getAllEvents();
      expect(events).toHaveLength(4);
      expect(events[0].eventMac).toBeUndefined();
      expect(events[1].eventMac).toBeUndefined();
      expect(events[2].eventMac).toMatch(/^[0-9a-f]{64}$/);
      expect(events[3].eventMac).toMatch(/^[0-9a-f]{64}$/);

      // Chain still verifies: hashes are intact across the boundary.
      expect(verifyChain(events, { key }).valid).toBe(true);
    } finally {
      store.close();
    }
  });

  it("schema migration is idempotent across reopens (user_version progresses to 2 then stays)", () => {
    let store = new SqliteAuditStore(dbPath);
    store.close();
    // Reopening should not error or rerun migrations.
    store = new SqliteAuditStore(dbPath);
    store.close();
    store = new SqliteAuditStore(dbPath, { macKey: key });
    store.close();
  });

  it("append() rejects events without eventMac when store has macKey configured", () => {
    const store = new SqliteAuditStore(dbPath, { macKey: key });
    try {
      const event: AuditEvent = {
        id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        sessionId: "s",
        serverName: "t",
        toolName: "x",
        toolArguments: {},
        policyDecision: "allow",
        policiesEvaluated: [],
        prevHash: null,
        eventHash: "deadbeef",
      };
      // append accepts caller-supplied events without computing MACs. With
      // a configured key it must refuse rows missing eventMac, otherwise it
      // would write rows that fail monotonicity at verify time.
      expect(() => store.append(event)).toThrow(/macKey but the event has no eventMac/);
    } finally {
      store.close();
    }
  });

  it("append() accepts events with eventMac when store has macKey configured", () => {
    const store = new SqliteAuditStore(dbPath, { macKey: key });
    try {
      const event: AuditEvent = {
        id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        sessionId: "s",
        serverName: "t",
        toolName: "x",
        toolArguments: {},
        policyDecision: "allow",
        policiesEvaluated: [],
        prevHash: null,
        eventHash: "deadbeef",
        eventMac: "abc123",
      };
      expect(() => store.append(event)).not.toThrow();
    } finally {
      store.close();
    }
  });
});

describe("audit_meta watermark (first_mac_seq)", () => {
  const key = Buffer.alloc(32, 7); // deterministic for assertions
  let tmpDir: string;
  let dbPath: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "mavryn-meta-"));
    dbPath = join(tmpDir, "test.db");
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  function appendOne(store: SqliteAuditStore, n: number) {
    return store.appendAtomic({
      id: crypto.randomUUID(),
      timestamp: new Date(2026, 0, n + 1).toISOString(),
      sessionId: "s",
      serverName: "t",
      toolName: "x",
      toolArguments: { n },
      policyDecision: "allow",
      policiesEvaluated: [],
    });
  }

  it("first_mac_seq is null on a store with no key configured", () => {
    const store = new SqliteAuditStore(dbPath);
    try {
      appendOne(store, 0);
      appendOne(store, 1);
      expect(store.getFirstMacSeq()).toBeNull();
    } finally {
      store.close();
    }
  });

  it("first_mac_seq is set on the seq of the first MAC'd write", () => {
    const store = new SqliteAuditStore(dbPath, { macKey: key });
    try {
      const first = appendOne(store, 0);
      appendOne(store, 1);
      appendOne(store, 2);
      expect(store.getFirstMacSeq()).toBe(first.seq);
    } finally {
      store.close();
    }
  });

  it("first_mac_seq does NOT advance on later writes", () => {
    const store = new SqliteAuditStore(dbPath, { macKey: key });
    try {
      const first = appendOne(store, 0);
      appendOne(store, 1);
      appendOne(store, 2);
      appendOne(store, 3);
      expect(store.getFirstMacSeq()).toBe(first.seq);
    } finally {
      store.close();
    }
  });

  it("captures the boundary correctly when key is added to an existing hash-only DB", () => {
    let store = new SqliteAuditStore(dbPath);
    appendOne(store, 0);
    appendOne(store, 1);
    expect(store.getFirstMacSeq()).toBeNull();
    store.close();

    store = new SqliteAuditStore(dbPath, { macKey: key });
    try {
      const firstMaced = appendOne(store, 2);
      expect(store.getFirstMacSeq()).toBe(firstMaced.seq);
      // The seq should be 3 (1-indexed AUTOINCREMENT after 2 prior rows).
      expect(firstMaced.seq).toBe(3);
    } finally {
      store.close();
    }
  });
});
