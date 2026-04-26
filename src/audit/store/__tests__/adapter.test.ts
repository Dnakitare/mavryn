import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { AuditLog } from "../../../logging/audit.js";
import { SqliteAuditStore } from "../index.js";
import { verifyChain } from "../../hash.js";
import type { Logger } from "../../../logging/logger.js";

function makeNoopLogger(): Logger {
  return {
    debug: () => {},
    info: () => {},
    warn: () => {},
    error: () => {},
    toolCall: () => {},
  } as unknown as Logger;
}

describe("AuditLog adapter integration", () => {
  let tmpDir: string;
  let dbPath: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "mavryn-adapter-"));
    dbPath = join(tmpDir, "audit.db");
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("records toolCall, toolDenied, and tool error to the chained store", () => {
    const audit = new AuditLog(true, dbPath, makeNoopLogger(), "test-session");

    audit.toolCall({
      upstream: "github",
      tool: "create_issue",
      namespacedTool: "github__create_issue",
      args: { title: "bug" },
      success: true,
      latencyMs: 120,
    });

    audit.toolDenied({
      upstream: "github",
      tool: "delete_repo",
      namespacedTool: "github__delete_repo",
      args: { repo: "main" },
      reason: "destructive operations are blocked",
    });

    audit.toolCall({
      upstream: "fs",
      tool: "read_file",
      namespacedTool: "fs__read_file",
      args: { path: "/etc/hosts" },
      success: false,
      latencyMs: 8,
      error: "ENOENT",
    });

    audit.close();

    const store = new SqliteAuditStore(dbPath);
    try {
      const events = store.getAllEvents();
      expect(events).toHaveLength(3);

      expect(events[0].policyDecision).toBe("allow");
      expect(events[0].resultStatus).toBe("success");
      expect(events[0].toolName).toBe("create_issue");
      expect(events[0].serverName).toBe("github");
      expect(events[0].toolArguments).toEqual({ title: "bug" });

      expect(events[1].policyDecision).toBe("deny");
      expect(events[1].resultStatus).toBe("blocked");
      expect(events[1].policyReason).toBe("destructive operations are blocked");

      expect(events[2].policyDecision).toBe("allow");
      expect(events[2].resultStatus).toBe("error");
      expect(events[2].resultSummary).toBe("ENOENT");

      // All three events share the session ID generated at adapter construction
      expect(events[0].sessionId).toBe("test-session");
      expect(events[1].sessionId).toBe("test-session");
      expect(events[2].sessionId).toBe("test-session");

      // Chain is intact end-to-end
      const { valid } = verifyChain(events);
      expect(valid).toBe(true);
    } finally {
      store.close();
    }
  });

  it("flags redactionsApplied=true when secrets were scrubbed (DSAR truthfulness)", () => {
    const audit = new AuditLog(true, dbPath, makeNoopLogger(), "redact-flag-session");

    // Row 1: contains a GitHub PAT — redactionsApplied should be true
    audit.toolCall({
      upstream: "github",
      tool: "auth",
      namespacedTool: "github__auth",
      args: { token: "ghp_abcdefghijklmnopqrstuvwxyz0123456789" },
      success: true,
      latencyMs: 10,
    });

    // Row 2: contains no secrets — redactionsApplied should be false
    audit.toolCall({
      upstream: "fs",
      tool: "read_file",
      namespacedTool: "fs__read_file",
      args: { path: "/etc/hosts" },
      success: true,
      latencyMs: 5,
    });

    // Row 3: secret hides in resultSummary (error message)
    audit.toolCall({
      upstream: "fs",
      tool: "read_file",
      namespacedTool: "fs__read_file",
      args: { path: "/etc/hosts" },
      success: false,
      latencyMs: 5,
      error: "auth failed: ghp_abcdefghijklmnopqrstuvwxyz0123456789",
    });

    audit.close();

    const store = new SqliteAuditStore(dbPath);
    try {
      const events = store.getAllEvents();
      expect(events[0].redactionsApplied).toBe(true);
      expect(events[1].redactionsApplied).toBe(false);
      expect(events[2].redactionsApplied).toBe(true);
    } finally {
      store.close();
    }
  });

  it("redacts secrets in tool arguments before storing + hashing", () => {
    const audit = new AuditLog(true, dbPath, makeNoopLogger(), "redact-session");

    audit.toolCall({
      upstream: "github",
      tool: "auth",
      namespacedTool: "github__auth",
      args: { token: "ghp_abcdefghijklmnopqrstuvwxyz0123456789" },
      success: true,
      latencyMs: 12,
    });

    audit.close();

    const store = new SqliteAuditStore(dbPath);
    try {
      const events = store.getAllEvents();
      expect(events).toHaveLength(1);
      const stored = events[0].toolArguments.token as string;
      expect(stored).not.toContain("ghp_abcdef");
      expect(stored).toMatch(/REDACTED/);
    } finally {
      store.close();
    }
  });

  it("survives audit failures without crashing — disables itself once on error", () => {
    // Point at an invalid path (a directory that exists as a file) to force open failure
    const badPath = join(tmpDir, "nonexistent-subdir-not-created", "audit.db");
    // Don't pre-create the parent — adapter should mkdirSync. So construct a path
    // where mkdirSync would fail: parent path is a file.
    const fileAsParent = join(tmpDir, "a-file");
    require("fs").writeFileSync(fileAsParent, "");
    const wedgedPath = join(fileAsParent, "audit.db");

    const audit = new AuditLog(true, wedgedPath, makeNoopLogger());

    // First call triggers ensureStore which fails — should not throw
    expect(() =>
      audit.toolCall({
        upstream: "x",
        tool: "y",
        namespacedTool: "x__y",
        args: {},
        success: true,
        latencyMs: 1,
      }),
    ).not.toThrow();

    audit.close();
  });

  it("propagates agentId from config to every audit row (Nadia / fleet-identity convention)", () => {
    const audit = new AuditLog(true, dbPath, makeNoopLogger(), "agent-session", "security_reviewer");

    audit.toolCall({
      upstream: "github",
      tool: "create_issue",
      namespacedTool: "github__create_issue",
      args: {},
      success: true,
      latencyMs: 1,
    });
    audit.toolDenied({
      upstream: "github",
      tool: "delete_repo",
      namespacedTool: "github__delete_repo",
      args: {},
      reason: "blocked",
    });
    audit.close();

    const store = new SqliteAuditStore(dbPath);
    try {
      const events = store.getAllEvents();
      expect(events).toHaveLength(2);
      expect(events[0].agentId).toBe("security_reviewer");
      expect(events[1].agentId).toBe("security_reviewer");
    } finally {
      store.close();
    }
  });

  it("chain remains intact across an audit close/reopen cycle (process restart simulation)", () => {
    // First "process": write two events
    const phase1 = new AuditLog(true, dbPath, makeNoopLogger(), "session-1");
    phase1.toolCall({
      upstream: "fs",
      tool: "read_file",
      namespacedTool: "fs__read_file",
      args: { path: "/a" },
      success: true,
      latencyMs: 10,
    });
    phase1.toolCall({
      upstream: "fs",
      tool: "read_file",
      namespacedTool: "fs__read_file",
      args: { path: "/b" },
      success: true,
      latencyMs: 12,
    });
    phase1.close();

    // Second "process": same DB file, new adapter instance, new sessionId
    const phase2 = new AuditLog(true, dbPath, makeNoopLogger(), "session-2");
    phase2.toolCall({
      upstream: "fs",
      tool: "read_file",
      namespacedTool: "fs__read_file",
      args: { path: "/c" },
      success: true,
      latencyMs: 15,
    });
    phase2.toolDenied({
      upstream: "fs",
      tool: "delete_file",
      namespacedTool: "fs__delete_file",
      args: { path: "/d" },
      reason: "destructive blocked",
    });
    phase2.close();

    // Verify the chain walks cleanly across the restart boundary
    const store = new SqliteAuditStore(dbPath);
    try {
      const events = store.getAllEvents();
      expect(events).toHaveLength(4);
      expect(events[0].sessionId).toBe("session-1");
      expect(events[1].sessionId).toBe("session-1");
      expect(events[2].sessionId).toBe("session-2");
      expect(events[3].sessionId).toBe("session-2");

      // The phase-2 chain must reference the phase-1 tail's hash
      expect(events[2].prevHash).toBe(events[1].eventHash);

      const { valid } = verifyChain(events);
      expect(valid).toBe(true);
    } finally {
      store.close();
    }
  });

  it("threads policiesEvaluated through to the audit row", () => {
    const audit = new AuditLog(true, dbPath, makeNoopLogger(), "policies-session");

    audit.toolCall({
      upstream: "github",
      tool: "create_issue",
      namespacedTool: "github__create_issue",
      args: { title: "bug" },
      success: true,
      latencyMs: 50,
      policiesEvaluated: ["log-all-writes", "block-prod-pushes"],
    });

    audit.toolDenied({
      upstream: "github",
      tool: "delete_repo",
      namespacedTool: "github__delete_repo",
      args: { repo: "main" },
      reason: "destructive ops blocked",
      policiesEvaluated: ["log-all-writes", "block-destructive"],
    });

    audit.close();

    const store = new SqliteAuditStore(dbPath);
    try {
      const events = store.getAllEvents();
      expect(events[0].policiesEvaluated).toEqual(["log-all-writes", "block-prod-pushes"]);
      expect(events[1].policiesEvaluated).toEqual(["log-all-writes", "block-destructive"]);
    } finally {
      store.close();
    }
  });

  it("isHealthy() reports true while audit is writing successfully", () => {
    const audit = new AuditLog(true, dbPath, makeNoopLogger(), "health-session");
    expect(audit.isHealthy()).toBe(true);

    audit.toolCall({
      upstream: "github",
      tool: "create_issue",
      namespacedTool: "github__create_issue",
      args: {},
      success: true,
      latencyMs: 1,
    });
    expect(audit.isHealthy()).toBe(true);
    audit.close();
  });

  it("isHealthy() flips to false after the store fails to open (init+failClosed compliance gate)", () => {
    // Wedge the path: parent is a file, so mkdirSync inside ensureStore fails
    const fileAsParent = join(tmpDir, "wedge-file");
    require("fs").writeFileSync(fileAsParent, "");
    const wedgedPath = join(fileAsParent, "audit.db");

    const audit = new AuditLog(true, wedgedPath, makeNoopLogger());

    // init() eagerly tries to open; failure flips writeable/healthy
    audit.init();
    expect(audit.isHealthy()).toBe(false);

    audit.close();
  });

  it("disabled audit reports healthy regardless (no DB to be sick)", () => {
    const audit = new AuditLog(false, dbPath, makeNoopLogger());
    expect(audit.isHealthy()).toBe(true);
    audit.close();
  });

  it("disabled adapter writes nothing and never opens the DB", () => {
    const audit = new AuditLog(false, dbPath, makeNoopLogger());

    audit.toolCall({
      upstream: "github",
      tool: "anything",
      namespacedTool: "github__anything",
      args: {},
      success: true,
      latencyMs: 1,
    });

    audit.close();

    // DB file should never have been created
    expect(require("fs").existsSync(dbPath)).toBe(false);
  });
});
