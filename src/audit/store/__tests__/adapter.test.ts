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
