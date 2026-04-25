import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { SqliteAuditStore } from "../sqlite.js";
import { computeEventHash, verifyChain } from "../../hash.js";
import type { AuditEvent } from "../../types.js";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

function makeEvent(overrides: Partial<AuditEvent> = {}, prevHash: string | null = null): AuditEvent {
  const base = {
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    sessionId: "sess-1",
    serverName: "test-server",
    toolName: "read_file",
    toolArguments: { path: "/tmp/test.txt" },
    policyDecision: "allow" as const,
    policiesEvaluated: ["log-all"],
    prevHash,
    eventHash: "",
  };

  const merged = { ...base, ...overrides, prevHash: overrides.prevHash ?? prevHash };

  merged.eventHash = computeEventHash({
    id: merged.id,
    timestamp: merged.timestamp,
    sessionId: merged.sessionId,
    serverName: merged.serverName,
    toolName: merged.toolName,
    toolArguments: merged.toolArguments,
    policyDecision: merged.policyDecision,
    prevHash: merged.prevHash,
  });

  return merged;
}

describe("SqliteAuditStore", () => {
  let store: SqliteAuditStore;
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "mavryn-test-"));
    store = new SqliteAuditStore(join(tmpDir, "test.db"));
  });

  afterEach(() => {
    store.close();
    rmSync(tmpDir, { recursive: true, force: true });
  });

  describe("append and retrieve", () => {
    it("stores and retrieves an event", () => {
      const event = makeEvent();
      store.append(event);

      const events = store.getAllEvents();
      expect(events).toHaveLength(1);
      expect(events[0].id).toBe(event.id);
      expect(events[0].toolName).toBe("read_file");
      expect(events[0].toolArguments).toEqual({ path: "/tmp/test.txt" });
    });

    it("preserves all fields through round-trip", () => {
      const event = makeEvent({
        agentId: "agent-1",
        toolAnnotations: { readOnly: true, destructive: false },
        policyReason: "Allowed by default",
        resultStatus: "success",
        resultSummary: "File read successfully",
        resultLatencyMs: 42,
      });
      store.append(event);

      const retrieved = store.getAllEvents()[0];
      expect(retrieved.agentId).toBe("agent-1");
      expect(retrieved.toolAnnotations).toEqual({ readOnly: true, destructive: false });
      expect(retrieved.policyReason).toBe("Allowed by default");
      expect(retrieved.resultStatus).toBe("success");
      expect(retrieved.resultSummary).toBe("File read successfully");
      expect(retrieved.resultLatencyMs).toBe(42);
      expect(retrieved.eventHash).toBe(event.eventHash);
      expect(retrieved.prevHash).toBe(event.prevHash);
    });
  });

  describe("getLatestHash", () => {
    it("returns null for empty store", () => {
      expect(store.getLatestHash()).toBeNull();
    });

    it("returns the hash of the most recent event", () => {
      const e1 = makeEvent({ timestamp: "2026-03-27T00:00:01.000Z" });
      store.append(e1);

      const e2 = makeEvent({ timestamp: "2026-03-27T00:00:02.000Z" }, e1.eventHash);
      store.append(e2);

      expect(store.getLatestHash()).toBe(e2.eventHash);
    });
  });

  describe("getEventCount", () => {
    it("returns 0 for empty store", () => {
      expect(store.getEventCount()).toBe(0);
    });

    it("returns correct count", () => {
      store.append(makeEvent());
      store.append(makeEvent());
      store.append(makeEvent());
      expect(store.getEventCount()).toBe(3);
    });
  });

  describe("query filters", () => {
    beforeEach(() => {
      store.append(
        makeEvent({
          id: "00000000-0000-0000-0000-000000000001",
          sessionId: "sess-1",
          serverName: "git-server",
          toolName: "git_push",
          policyDecision: "deny",
          timestamp: "2026-03-27T00:00:01.000Z",
        }),
      );
      store.append(
        makeEvent({
          id: "00000000-0000-0000-0000-000000000002",
          sessionId: "sess-1",
          serverName: "fs-server",
          toolName: "read_file",
          policyDecision: "allow",
          timestamp: "2026-03-27T00:00:02.000Z",
        }),
      );
      store.append(
        makeEvent({
          id: "00000000-0000-0000-0000-000000000003",
          sessionId: "sess-2",
          serverName: "fs-server",
          toolName: "write_file",
          policyDecision: "allow",
          timestamp: "2026-03-27T00:00:03.000Z",
        }),
      );
    });

    it("filters by sessionId", () => {
      const results = store.query({ sessionId: "sess-2" });
      expect(results).toHaveLength(1);
      expect(results[0].toolName).toBe("write_file");
    });

    it("filters by serverName", () => {
      const results = store.query({ serverName: "git-server" });
      expect(results).toHaveLength(1);
      expect(results[0].toolName).toBe("git_push");
    });

    it("filters by toolName", () => {
      const results = store.query({ toolName: "read_file" });
      expect(results).toHaveLength(1);
    });

    it("filters by policyDecision", () => {
      const results = store.query({ policyDecision: "deny" });
      expect(results).toHaveLength(1);
      expect(results[0].toolName).toBe("git_push");
    });

    it("filters by timestamp range", () => {
      const results = store.query({
        fromTimestamp: "2026-03-27T00:00:02.000Z",
        toTimestamp: "2026-03-27T00:00:03.000Z",
      });
      expect(results).toHaveLength(2);
    });

    it("applies limit and offset", () => {
      const results = store.query({ limit: 1, offset: 0 });
      expect(results).toHaveLength(1);
    });

    it("combines multiple filters", () => {
      const results = store.query({
        sessionId: "sess-1",
        policyDecision: "allow",
      });
      expect(results).toHaveLength(1);
      expect(results[0].toolName).toBe("read_file");
    });
  });

  describe("getSessionIds", () => {
    it("returns empty array for empty store", () => {
      expect(store.getSessionIds()).toEqual([]);
    });

    it("returns unique session IDs", () => {
      store.append(makeEvent({ sessionId: "sess-a", timestamp: "2026-03-27T00:00:01.000Z" }));
      store.append(makeEvent({ sessionId: "sess-b", timestamp: "2026-03-27T00:00:02.000Z" }));
      store.append(makeEvent({ sessionId: "sess-a", timestamp: "2026-03-27T00:00:03.000Z" }));

      const sessions = store.getSessionIds();
      expect(sessions).toHaveLength(2);
      expect(sessions).toContain("sess-a");
      expect(sessions).toContain("sess-b");
    });
  });

  describe("getAllEvents pagination", () => {
    it("respects limit and offset", () => {
      for (let i = 0; i < 5; i++) {
        store.append(makeEvent({ timestamp: `2026-03-27T00:00:0${i}.000Z` }));
      }

      const page = store.getAllEvents(2, 1);
      expect(page).toHaveLength(2);
    });
  });

  describe("appendAtomic", () => {
    it("returns event with computed prevHash and eventHash", () => {
      const event = store.appendAtomic({
        id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        sessionId: "sess-1",
        serverName: "test-server",
        toolName: "read_file",
        toolArguments: { path: "/test" },
        policyDecision: "allow",
        policiesEvaluated: ["log-all"],
      });

      expect(event.prevHash).toBeNull();
      expect(event.eventHash).toMatch(/^[a-f0-9]{64}$/);
      expect(event.toolName).toBe("read_file");
    });

    it("chains hashes across multiple calls", () => {
      const e1 = store.appendAtomic({
        id: crypto.randomUUID(),
        timestamp: "2026-03-27T00:00:01.000Z",
        sessionId: "sess-1",
        serverName: "test-server",
        toolName: "tool_1",
        toolArguments: {},
        policyDecision: "allow",
        policiesEvaluated: [],
      });

      const e2 = store.appendAtomic({
        id: crypto.randomUUID(),
        timestamp: "2026-03-27T00:00:02.000Z",
        sessionId: "sess-1",
        serverName: "test-server",
        toolName: "tool_2",
        toolArguments: {},
        policyDecision: "allow",
        policiesEvaluated: [],
      });

      const e3 = store.appendAtomic({
        id: crypto.randomUUID(),
        timestamp: "2026-03-27T00:00:03.000Z",
        sessionId: "sess-1",
        serverName: "test-server",
        toolName: "tool_3",
        toolArguments: {},
        policyDecision: "deny",
        policiesEvaluated: ["block-writes"],
        resultStatus: "blocked",
      });

      expect(e1.prevHash).toBeNull();
      expect(e2.prevHash).toBe(e1.eventHash);
      expect(e3.prevHash).toBe(e2.eventHash);

      const allEvents = store.getAllEvents();
      expect(allEvents).toHaveLength(3);

      const { valid } = verifyChain(allEvents);
      expect(valid).toBe(true);
    });

    it("persists events retrievable by query", () => {
      store.appendAtomic({
        id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        sessionId: "sess-1",
        serverName: "git-server",
        toolName: "git_push",
        toolArguments: { branch: "main" },
        policyDecision: "deny",
        policyReason: "Protected branch",
        policiesEvaluated: ["block-main-push"],
        resultStatus: "blocked",
      });

      expect(store.getEventCount()).toBe(1);
      const results = store.query({ policyDecision: "deny" });
      expect(results).toHaveLength(1);
      expect(results[0].policyReason).toBe("Protected branch");
    });
  });

  describe("SDK-forward-compat columns (turnId, assistantMessage, systemPromptHash, meta)", () => {
    it("round-trips all four columns", () => {
      const event = store.appendAtomic({
        id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        sessionId: "sess-1",
        serverName: "github",
        toolName: "create_issue",
        toolArguments: { title: "bug" },
        policyDecision: "allow",
        policiesEvaluated: [],
        turnId: "turn-abc-123",
        assistantMessage: "I'll file an issue for the user's bug report.",
        systemPromptHash: "sha256:0123456789abcdef",
        meta: { agent_version: "1.2.3", deployment: "prod", commit: "abcd123" },
      });

      const retrieved = store.getAllEvents()[0];
      expect(retrieved.turnId).toBe("turn-abc-123");
      expect(retrieved.assistantMessage).toBe("I'll file an issue for the user's bug report.");
      expect(retrieved.systemPromptHash).toBe("sha256:0123456789abcdef");
      expect(retrieved.meta).toEqual({ agent_version: "1.2.3", deployment: "prod", commit: "abcd123" });
      expect(retrieved.eventHash).toBe(event.eventHash);
    });

    it("treats undefined SDK fields as nullable, not required", () => {
      const event = store.appendAtomic({
        id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        sessionId: "sess-1",
        serverName: "fs",
        toolName: "read_file",
        toolArguments: {},
        policyDecision: "allow",
        policiesEvaluated: [],
      });

      const retrieved = store.getAllEvents()[0];
      expect(retrieved.turnId).toBeUndefined();
      expect(retrieved.assistantMessage).toBeUndefined();
      expect(retrieved.systemPromptHash).toBeUndefined();
      expect(retrieved.meta).toBeUndefined();
      expect(retrieved.eventHash).toBe(event.eventHash);
    });

    it("includes turnId in the hash — tampering invalidates verification", () => {
      const event = store.appendAtomic({
        id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        sessionId: "sess-1",
        serverName: "fs",
        toolName: "read_file",
        toolArguments: {},
        policyDecision: "allow",
        policiesEvaluated: [],
        turnId: "turn-real",
      });

      const tamperedHash = computeEventHash({
        id: event.id,
        timestamp: event.timestamp,
        sessionId: event.sessionId,
        serverName: event.serverName,
        toolName: event.toolName,
        toolArguments: event.toolArguments,
        policyDecision: event.policyDecision,
        policiesEvaluated: event.policiesEvaluated,
        turnId: "turn-fake",
        prevHash: event.prevHash,
      });

      expect(tamperedHash).not.toBe(event.eventHash);
    });

    it("includes assistantMessage in the hash", () => {
      const event = store.appendAtomic({
        id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        sessionId: "sess-1",
        serverName: "fs",
        toolName: "read_file",
        toolArguments: {},
        policyDecision: "allow",
        policiesEvaluated: [],
        assistantMessage: "I'll read the file as requested",
      });

      const tamperedHash = computeEventHash({
        id: event.id,
        timestamp: event.timestamp,
        sessionId: event.sessionId,
        serverName: event.serverName,
        toolName: event.toolName,
        toolArguments: event.toolArguments,
        policyDecision: event.policyDecision,
        policiesEvaluated: event.policiesEvaluated,
        assistantMessage: "I'll exfiltrate the file",
        prevHash: event.prevHash,
      });

      expect(tamperedHash).not.toBe(event.eventHash);
    });

    it("includes systemPromptHash in the hash", () => {
      const event = store.appendAtomic({
        id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        sessionId: "sess-1",
        serverName: "fs",
        toolName: "read_file",
        toolArguments: {},
        policyDecision: "allow",
        policiesEvaluated: [],
        systemPromptHash: "sha256:original",
      });

      const tamperedHash = computeEventHash({
        id: event.id,
        timestamp: event.timestamp,
        sessionId: event.sessionId,
        serverName: event.serverName,
        toolName: event.toolName,
        toolArguments: event.toolArguments,
        policyDecision: event.policyDecision,
        policiesEvaluated: event.policiesEvaluated,
        systemPromptHash: "sha256:swapped-prompt",
        prevHash: event.prevHash,
      });

      expect(tamperedHash).not.toBe(event.eventHash);
    });

    it("includes meta in the hash, with key-order independence", () => {
      const event = store.appendAtomic({
        id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        sessionId: "sess-1",
        serverName: "fs",
        toolName: "read_file",
        toolArguments: {},
        policyDecision: "allow",
        policiesEvaluated: [],
        meta: { commit: "abc", deployment: "prod" },
      });

      // Same logical meta, different key order — same hash (RFC 8785)
      const sameHash = computeEventHash({
        id: event.id,
        timestamp: event.timestamp,
        sessionId: event.sessionId,
        serverName: event.serverName,
        toolName: event.toolName,
        toolArguments: event.toolArguments,
        policyDecision: event.policyDecision,
        policiesEvaluated: event.policiesEvaluated,
        meta: { deployment: "prod", commit: "abc" },
        prevHash: event.prevHash,
      });

      expect(sameHash).toBe(event.eventHash);

      // Different value — different hash
      const tamperedHash = computeEventHash({
        id: event.id,
        timestamp: event.timestamp,
        sessionId: event.sessionId,
        serverName: event.serverName,
        toolName: event.toolName,
        toolArguments: event.toolArguments,
        policyDecision: event.policyDecision,
        policiesEvaluated: event.policiesEvaluated,
        meta: { commit: "abc", deployment: "staging" },
        prevHash: event.prevHash,
      });

      expect(tamperedHash).not.toBe(event.eventHash);
    });

    it("filters by turnId via query()", () => {
      const turnA = "turn-aaa";
      const turnB = "turn-bbb";

      for (const turn of [turnA, turnA, turnB, turnA]) {
        store.appendAtomic({
          id: crypto.randomUUID(),
          timestamp: new Date(Date.now() + Math.random()).toISOString(),
          sessionId: "sess-1",
          serverName: "fs",
          toolName: "read_file",
          toolArguments: {},
          policyDecision: "allow",
          policiesEvaluated: [],
          turnId: turn,
        });
      }

      expect(store.query({ turnId: turnA })).toHaveLength(3);
      expect(store.query({ turnId: turnB })).toHaveLength(1);
    });
  });

  describe("attribution columns (userId, sourceTag, promptContext)", () => {
    it("round-trips userId, sourceTag, and promptContext", () => {
      const event = store.appendAtomic({
        id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        sessionId: "sess-1",
        serverName: "fs-server",
        toolName: "read_file",
        toolArguments: { path: "/etc/hosts" },
        policyDecision: "allow",
        policiesEvaluated: [],
        userId: "alice@example.com",
        sourceTag: "ops-copilot",
        promptContext: "diagnose flaky test on staging",
      });

      const retrieved = store.getAllEvents()[0];
      expect(retrieved.userId).toBe("alice@example.com");
      expect(retrieved.sourceTag).toBe("ops-copilot");
      expect(retrieved.promptContext).toBe("diagnose flaky test on staging");
      expect(retrieved.eventHash).toBe(event.eventHash);
    });

    it("treats undefined attribution fields as nullable, not required", () => {
      const event = store.appendAtomic({
        id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        sessionId: "sess-1",
        serverName: "fs-server",
        toolName: "read_file",
        toolArguments: {},
        policyDecision: "allow",
        policiesEvaluated: [],
      });

      const retrieved = store.getAllEvents()[0];
      expect(retrieved.userId).toBeUndefined();
      expect(retrieved.sourceTag).toBeUndefined();
      expect(retrieved.promptContext).toBeUndefined();
      expect(retrieved.eventHash).toBe(event.eventHash);
    });

    it("includes userId in the hash — tampering with it invalidates verification", () => {
      const event = store.appendAtomic({
        id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        sessionId: "sess-1",
        serverName: "fs-server",
        toolName: "read_file",
        toolArguments: {},
        policyDecision: "allow",
        policiesEvaluated: [],
        userId: "alice@example.com",
      });

      // Re-hashing with a different userId must produce a different hash
      const tamperedHash = computeEventHash({
        id: event.id,
        timestamp: event.timestamp,
        sessionId: event.sessionId,
        serverName: event.serverName,
        toolName: event.toolName,
        toolArguments: event.toolArguments,
        policyDecision: event.policyDecision,
        policiesEvaluated: event.policiesEvaluated,
        userId: "mallory@example.com",
        prevHash: event.prevHash,
      });

      expect(tamperedHash).not.toBe(event.eventHash);
    });

    it("includes sourceTag in the hash", () => {
      const event = store.appendAtomic({
        id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        sessionId: "sess-1",
        serverName: "fs-server",
        toolName: "read_file",
        toolArguments: {},
        policyDecision: "allow",
        policiesEvaluated: [],
        sourceTag: "security_reviewer",
      });

      const tamperedHash = computeEventHash({
        id: event.id,
        timestamp: event.timestamp,
        sessionId: event.sessionId,
        serverName: event.serverName,
        toolName: event.toolName,
        toolArguments: event.toolArguments,
        policyDecision: event.policyDecision,
        policiesEvaluated: event.policiesEvaluated,
        sourceTag: "release_notes_drafter",
        prevHash: event.prevHash,
      });

      expect(tamperedHash).not.toBe(event.eventHash);
    });

    it("includes promptContext in the hash", () => {
      const event = store.appendAtomic({
        id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        sessionId: "sess-1",
        serverName: "fs-server",
        toolName: "read_file",
        toolArguments: {},
        policyDecision: "allow",
        policiesEvaluated: [],
        promptContext: "investigate billing bug",
      });

      const tamperedHash = computeEventHash({
        id: event.id,
        timestamp: event.timestamp,
        sessionId: event.sessionId,
        serverName: event.serverName,
        toolName: event.toolName,
        toolArguments: event.toolArguments,
        policyDecision: event.policyDecision,
        policiesEvaluated: event.policiesEvaluated,
        promptContext: "exfiltrate user data",
        prevHash: event.prevHash,
      });

      expect(tamperedHash).not.toBe(event.eventHash);
    });

    it("verifies cleanly when two events share a timestamp (regression: chain must order by seq, not timestamp)", () => {
      const sharedTimestamp = "2026-04-25T12:00:00.000Z";

      const e1 = store.appendAtomic({
        id: crypto.randomUUID(),
        timestamp: sharedTimestamp,
        sessionId: "sess-1",
        serverName: "fs-server",
        toolName: "read_file",
        toolArguments: { path: "/a" },
        policyDecision: "allow",
        policiesEvaluated: [],
      });

      const e2 = store.appendAtomic({
        id: crypto.randomUUID(),
        timestamp: sharedTimestamp,
        sessionId: "sess-1",
        serverName: "fs-server",
        toolName: "read_file",
        toolArguments: { path: "/b" },
        policyDecision: "allow",
        policiesEvaluated: [],
      });

      const e3 = store.appendAtomic({
        id: crypto.randomUUID(),
        timestamp: sharedTimestamp,
        sessionId: "sess-1",
        serverName: "fs-server",
        toolName: "read_file",
        toolArguments: { path: "/c" },
        policyDecision: "allow",
        policiesEvaluated: [],
      });

      // seq must be assigned in insertion order regardless of timestamp ties
      expect(e1.seq).toBeDefined();
      expect(e2.seq).toBe((e1.seq ?? 0) + 1);
      expect(e3.seq).toBe((e2.seq ?? 0) + 1);

      // Chain must verify even with identical timestamps
      const all = store.getAllEvents();
      expect(all.map((e) => e.toolArguments.path)).toEqual(["/a", "/b", "/c"]);
      expect(verifyChain(all).valid).toBe(true);
    });

    it("hashes the same regardless of object key insertion order (RFC 8785 JCS)", () => {
      // Same logical args, different insertion order — must produce identical hashes.
      const e1 = store.appendAtomic({
        id: "00000000-0000-0000-0000-aaaaaaaaaaaa",
        timestamp: "2026-04-25T00:00:00.000Z",
        sessionId: "sess-1",
        serverName: "fs",
        toolName: "read_file",
        toolArguments: { path: "/etc/hosts", mode: "r", limit: 100 },
        policyDecision: "allow",
        policiesEvaluated: [],
      });

      // Fresh store so e2 also starts a chain (prevHash == null)
      store.close();
      tmpDir = mkdtempSync(join(tmpdir(), "mavryn-test-"));
      store = new SqliteAuditStore(join(tmpDir, "test.db"));

      const e2 = store.appendAtomic({
        id: "00000000-0000-0000-0000-aaaaaaaaaaaa",
        timestamp: "2026-04-25T00:00:00.000Z",
        sessionId: "sess-1",
        serverName: "fs",
        toolName: "read_file",
        toolArguments: { limit: 100, mode: "r", path: "/etc/hosts" },
        policyDecision: "allow",
        policiesEvaluated: [],
      });

      expect(e1.eventHash).toBe(e2.eventHash);
    });

    it("hashes integer-like object keys deterministically (regression for V8 numeric-key reordering)", () => {
      const argsA = { "10": "ten", "2": "two", "1": "one" };
      const argsB = { "1": "one", "10": "ten", "2": "two" };

      const h1 = computeEventHash({
        id: "fixed-id",
        timestamp: "2026-04-25T00:00:00.000Z",
        sessionId: "s",
        serverName: "x",
        toolName: "t",
        toolArguments: argsA,
        policyDecision: "allow",
        prevHash: null,
      });

      const h2 = computeEventHash({
        id: "fixed-id",
        timestamp: "2026-04-25T00:00:00.000Z",
        sessionId: "s",
        serverName: "x",
        toolName: "t",
        toolArguments: argsB,
        policyDecision: "allow",
        prevHash: null,
      });

      expect(h1).toBe(h2);
    });

    it("hashes nested objects with reordered keys deterministically", () => {
      const h1 = computeEventHash({
        id: "fixed-id",
        timestamp: "2026-04-25T00:00:00.000Z",
        sessionId: "s",
        serverName: "x",
        toolName: "t",
        toolArguments: {
          query: "select 1",
          options: { timeout: 5000, retries: 3, headers: { "x-trace": "abc", "x-user": "alice" } },
        },
        policyDecision: "allow",
        prevHash: null,
      });

      const h2 = computeEventHash({
        id: "fixed-id",
        timestamp: "2026-04-25T00:00:00.000Z",
        sessionId: "s",
        serverName: "x",
        toolName: "t",
        toolArguments: {
          options: { headers: { "x-user": "alice", "x-trace": "abc" }, retries: 3, timeout: 5000 },
          query: "select 1",
        },
        policyDecision: "allow",
        prevHash: null,
      });

      expect(h1).toBe(h2);
    });

    it("survives a JSON.parse(JSON.stringify(args)) round-trip (cross-runtime audit verifier scenario)", () => {
      const original = {
        path: "/var/log/app.log",
        flags: { append: true, sync: false },
        tags: ["prod", "us-west-2"],
      };

      const e1 = store.appendAtomic({
        id: crypto.randomUUID(),
        timestamp: "2026-04-25T00:00:00.000Z",
        sessionId: "sess-1",
        serverName: "fs",
        toolName: "write_file",
        toolArguments: original,
        policyDecision: "allow",
        policiesEvaluated: [],
      });

      // Simulate a third-party verifier that reads the row, parses tool_arguments
      // from JSON, and tries to verify the chain. This was finding #2's
      // smoking-gun scenario.
      const fromDb = store.getAllEvents();
      const recomputed = computeEventHash({
        id: fromDb[0].id,
        timestamp: fromDb[0].timestamp,
        sessionId: fromDb[0].sessionId,
        serverName: fromDb[0].serverName,
        toolName: fromDb[0].toolName,
        toolArguments: fromDb[0].toolArguments,
        policyDecision: fromDb[0].policyDecision,
        policiesEvaluated: fromDb[0].policiesEvaluated,
        prevHash: fromDb[0].prevHash,
      });

      expect(recomputed).toBe(e1.eventHash);
    });

    it("verifyChain still succeeds across events with mixed attribution", () => {
      const e1 = store.appendAtomic({
        id: crypto.randomUUID(),
        timestamp: "2026-04-24T00:00:01.000Z",
        sessionId: "sess-1",
        serverName: "fs-server",
        toolName: "read_file",
        toolArguments: {},
        policyDecision: "allow",
        policiesEvaluated: [],
        userId: "alice@example.com",
      });

      const e2 = store.appendAtomic({
        id: crypto.randomUUID(),
        timestamp: "2026-04-24T00:00:02.000Z",
        sessionId: "sess-1",
        serverName: "fs-server",
        toolName: "write_file",
        toolArguments: {},
        policyDecision: "allow",
        policiesEvaluated: [],
        sourceTag: "ops-copilot",
      });

      const e3 = store.appendAtomic({
        id: crypto.randomUUID(),
        timestamp: "2026-04-24T00:00:03.000Z",
        sessionId: "sess-1",
        serverName: "fs-server",
        toolName: "delete_file",
        toolArguments: {},
        policyDecision: "deny",
        policiesEvaluated: ["block-destructive"],
        promptContext: "cleanup old logs",
      });

      expect(e2.prevHash).toBe(e1.eventHash);
      expect(e3.prevHash).toBe(e2.eventHash);

      const { valid } = verifyChain(store.getAllEvents());
      expect(valid).toBe(true);
    });
  });
});
