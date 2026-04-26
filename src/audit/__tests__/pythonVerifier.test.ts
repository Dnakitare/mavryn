import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { randomBytes } from "node:crypto";
import { SqliteAuditStore } from "../store/sqlite.js";

/**
 * Cross-implementation test: the Python reference verifier at
 * verifier/mavryn_verify.py must agree with the TypeScript verify on the
 * same DB. This is what makes the "third-party verifier" claim in the
 * threat model concrete — without this, JCS-portability is just words.
 *
 * Skips when python3 isn't on PATH so it doesn't break CI on systems where
 * Python isn't installed. CI should ensure python3 is present.
 */
const PYTHON_AVAILABLE = (() => {
  try {
    execFileSync("python3", ["--version"], { stdio: "pipe" });
    return true;
  } catch {
    return false;
  }
})();

const VERIFIER = resolve(__dirname, "..", "..", "..", "verifier", "mavryn_verify.py");

function runVerifier(args: string[]): { stdout: string; stderr: string; code: number } {
  try {
    const stdout = execFileSync("python3", [VERIFIER, ...args], {
      encoding: "utf-8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { stdout, stderr: "", code: 0 };
  } catch (e: any) {
    return {
      stdout: e.stdout?.toString() ?? "",
      stderr: e.stderr?.toString() ?? "",
      code: e.status ?? 1,
    };
  }
}

describe.skipIf(!PYTHON_AVAILABLE)("Python reference verifier ↔ TypeScript", () => {
  let tmpDir: string;
  let dbPath: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "mavryn-pyverify-"));
    dbPath = join(tmpDir, "audit.db");
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  function appendOne(store: SqliteAuditStore, n: number, args: Record<string, unknown> = {}) {
    return store.appendAtomic({
      id: `evt-${n}`,
      timestamp: `2026-01-${String(n + 1).padStart(2, "0")}T00:00:00.000Z`,
      sessionId: "sess",
      serverName: "fs",
      toolName: "read_file",
      toolArguments: { path: `/tmp/${n}`, ...args },
      policyDecision: "allow",
      policiesEvaluated: ["log-all"],
    });
  }

  it("verifies a hash-only DB (no key) and reports OK", () => {
    const store = new SqliteAuditStore(dbPath);
    for (let i = 0; i < 3; i++) appendOne(store, i);
    store.close();

    const r = runVerifier(["--db", dbPath]);
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/3 events verified - chain intact/);
    expect(r.stdout).toMatch(/hash-only; no key supplied/);
  });

  it("verifies a MAC'd DB with the correct key and reports MAC-verified", () => {
    const key = randomBytes(32);
    const store = new SqliteAuditStore(dbPath, { macKey: key });
    for (let i = 0; i < 3; i++) appendOne(store, i);
    store.close();

    const r = runVerifier(["--db", dbPath, "--key-base64", key.toString("base64")]);
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/3 events verified - chain intact, 3 MAC-verified/);
  });

  it("rejects a MAC'd DB when the wrong key is supplied", () => {
    const key = randomBytes(32);
    const wrongKey = randomBytes(32);
    const store = new SqliteAuditStore(dbPath, { macKey: key });
    for (let i = 0; i < 3; i++) appendOne(store, i);
    store.close();

    const r = runVerifier(["--db", dbPath, "--key-base64", wrongKey.toString("base64")]);
    expect(r.code).toBe(1);
    expect(r.stderr).toMatch(/MAC verification failed/);
  });

  it("verifies a mixed-boundary DB (legacy hash-only + MAC'd rows)", () => {
    const key = randomBytes(32);
    let store = new SqliteAuditStore(dbPath);
    for (let i = 0; i < 2; i++) appendOne(store, i);
    store.close();
    store = new SqliteAuditStore(dbPath, { macKey: key });
    for (let i = 2; i < 4; i++) appendOne(store, i);
    store.close();

    const r = runVerifier(["--db", dbPath, "--key-base64", key.toString("base64")]);
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/4 events verified - chain intact/);
    expect(r.stdout).toMatch(/2 MAC-verified, 2 legacy hash-only/);
    expect(r.stdout).toMatch(/First MAC at seq=3/);
  });

  it("detects content tampering (hash mismatch) when a row is modified directly", async () => {
    const store = new SqliteAuditStore(dbPath);
    for (let i = 0; i < 3; i++) appendOne(store, i);
    store.close();

    // Tamper directly with sqlite (bypass the store).
    const Database = (await import("better-sqlite3")).default;
    const db = new Database(dbPath);
    db.exec(`UPDATE events SET tool_arguments = '{"path":"/tampered"}' WHERE seq = 2`);
    db.close();

    const r = runVerifier(["--db", dbPath]);
    expect(r.code).toBe(1);
    expect(r.stderr).toMatch(/event_hash mismatch/);
  });

  it("detects MAC monotonicity violation (event_mac stripped on a row >= first_mac_seq)", async () => {
    const key = randomBytes(32);
    const store = new SqliteAuditStore(dbPath, { macKey: key });
    for (let i = 0; i < 3; i++) appendOne(store, i);
    store.close();

    const Database = (await import("better-sqlite3")).default;
    const db = new Database(dbPath);
    // Strip the MAC on row 2 only — recomputes nothing (the attacker has no
    // key). Without monotonicity this would silently pass as "legacy
    // hash-only"; with monotonicity the watermark says rows 1+ must be MAC'd.
    db.exec(`UPDATE events SET event_mac = NULL WHERE seq = 2`);
    db.close();

    const r = runVerifier(["--db", dbPath, "--key-base64", key.toString("base64")]);
    expect(r.code).toBe(1);
    expect(r.stderr).toMatch(/MAC monotonicity violated/);
  });

  it("detects watermark deletion (audit_meta wiped but rows still have MACs)", async () => {
    const key = randomBytes(32);
    const store = new SqliteAuditStore(dbPath, { macKey: key });
    for (let i = 0; i < 3; i++) appendOne(store, i);
    store.close();

    const Database = (await import("better-sqlite3")).default;
    const db = new Database(dbPath);
    db.exec("DELETE FROM audit_meta WHERE key = 'first_mac_seq'");
    db.close();

    const r = runVerifier(["--db", dbPath, "--key-base64", key.toString("base64")]);
    expect(r.code).toBe(1);
    expect(r.stderr).toMatch(/audit_meta\.first_mac_seq is missing but 3 rows have MACs/);
  });

  it("rejects a typo'd base64 key at CLI parse time (not silently)", () => {
    const store = new SqliteAuditStore(dbPath);
    appendOne(store, 0);
    store.close();
    // Same kind of garbage that pre-fix slipped through Buffer.from on JS side.
    const bad = "a".repeat(20) + "!" + "a".repeat(23);
    const r = runVerifier(["--db", dbPath, "--key-base64", bad]);
    expect(r.code).toBe(1);
    expect(r.stderr).toMatch(/non-base64 characters/);
  });

  it("payload format is byte-for-byte compatible: tool_arguments with nested objects round-trip", () => {
    const key = randomBytes(32);
    const store = new SqliteAuditStore(dbPath, { macKey: key });
    appendOne(store, 0, {
      nested: { a: 1, b: ["x", "y"], c: { z: "deep" } },
      flag: true,
      count: 42,
      maybe: null,
    });
    store.close();

    const r = runVerifier(["--db", dbPath, "--key-base64", key.toString("base64")]);
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/1 events verified - chain intact, 1 MAC-verified/);
  });
});
