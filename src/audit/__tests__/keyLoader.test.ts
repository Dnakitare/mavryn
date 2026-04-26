import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { randomBytes } from "node:crypto";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { loadMacKey, loadMacKeyFromConfig, MacKeyLoadError } from "../keyLoader.js";

function writeKeyFile(filePath: string, content: string, mode = 0o400) {
  writeFileSync(filePath, content);
  chmodSync(filePath, mode);
}

describe("loadMacKey", () => {
  const ENV_VAR = "MAVRYN_TEST_KEY";
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "mavryn-key-"));
    delete process.env[ENV_VAR];
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
    delete process.env[ENV_VAR];
  });

  it("loads a 32-byte base64 key from env", () => {
    const key = randomBytes(32);
    process.env[ENV_VAR] = key.toString("base64");
    const loaded = loadMacKey({ source: "env", ref: ENV_VAR }, tmpDir);
    expect(loaded.length).toBe(32);
    expect(loaded.equals(key)).toBe(true);
  });

  it("throws when env var is unset", () => {
    expect(() => loadMacKey({ source: "env", ref: ENV_VAR }, tmpDir)).toThrow(MacKeyLoadError);
  });

  it("throws when env var is empty", () => {
    process.env[ENV_VAR] = "";
    expect(() => loadMacKey({ source: "env", ref: ENV_VAR }, tmpDir)).toThrow(MacKeyLoadError);
  });

  it("throws when key decodes to wrong byte length", () => {
    process.env[ENV_VAR] = Buffer.from("too-short").toString("base64");
    expect(() => loadMacKey({ source: "env", ref: ENV_VAR }, tmpDir)).toThrow(/32 bytes/);
  });

  it("rejects values with non-base64 characters even if they coincidentally decode to 32 bytes", () => {
    // Reproduces the original silent-acceptance bug: 'a' x20 + '!' + 'a' x23
    // is 44 chars; Buffer.from drops the '!' and decodes to exactly 32 bytes.
    // Pre-fix this passed; post-fix this is rejected at the regex.
    const pseudoBase64 = "a".repeat(20) + "!" + "a".repeat(23);
    process.env[ENV_VAR] = pseudoBase64;
    expect(() => loadMacKey({ source: "env", ref: ENV_VAR }, tmpDir)).toThrow(/non-base64 characters/);
  });

  it("rejects values containing whitespace inside the key body", () => {
    // 44 valid base64 chars, but with a space mid-string — decodes silently.
    const key = randomBytes(32).toString("base64");
    const middle = key.slice(0, 20) + " " + key.slice(20);
    process.env[ENV_VAR] = middle;
    expect(() => loadMacKey({ source: "env", ref: ENV_VAR }, tmpDir)).toThrow(/non-base64 characters/);
  });

  it("rejects smart-quote / curly-quote contamination", () => {
    const key = randomBytes(32).toString("base64");
    process.env[ENV_VAR] = key.replace(/[A-Za-z]/, "“"); // " (left double quote)
    expect(() => loadMacKey({ source: "env", ref: ENV_VAR }, tmpDir)).toThrow(/non-base64 characters/);
  });

  it("trims surrounding whitespace from env var values", () => {
    // docker run -e and similar can introduce trailing newlines.
    const key = randomBytes(32);
    process.env[ENV_VAR] = `  ${key.toString("base64")}\n`;
    const loaded = loadMacKey({ source: "env", ref: ENV_VAR }, tmpDir);
    expect(loaded.equals(key)).toBe(true);
  });

  it("loads a 32-byte base64 key from a file (relative path resolves against configDir)", () => {
    const key = randomBytes(32);
    const filename = "audit.key";
    writeKeyFile(join(tmpDir, filename), key.toString("base64"));
    const loaded = loadMacKey({ source: "file", ref: filename }, tmpDir);
    expect(loaded.equals(key)).toBe(true);
  });

  it("loads from absolute file paths too", () => {
    const key = randomBytes(32);
    const filePath = join(tmpDir, "abs.key");
    writeKeyFile(filePath, key.toString("base64"));
    const loaded = loadMacKey({ source: "file", ref: filePath }, "/some/other/dir");
    expect(loaded.equals(key)).toBe(true);
  });

  it("trims trailing whitespace/newlines from file content", () => {
    const key = randomBytes(32);
    writeKeyFile(join(tmpDir, "k"), key.toString("base64") + "\n\n");
    const loaded = loadMacKey({ source: "file", ref: "k" }, tmpDir);
    expect(loaded.equals(key)).toBe(true);
  });

  it("warns when key file is world-readable but still loads successfully", () => {
    const key = randomBytes(32);
    const filePath = join(tmpDir, "loose.key");
    writeKeyFile(filePath, key.toString("base64"), 0o644);
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      const loaded = loadMacKey({ source: "file", ref: filePath }, tmpDir);
      expect(loaded.equals(key)).toBe(true);
      expect(warnSpy).toHaveBeenCalledOnce();
      const msg = warnSpy.mock.calls[0][0] as string;
      expect(msg).toMatch(/mode 644/);
      expect(msg).toMatch(/expected 0400/);
    } finally {
      warnSpy.mockRestore();
    }
  });

  it("does not warn when key file is owner-only-readable", () => {
    const key = randomBytes(32);
    const filePath = join(tmpDir, "tight.key");
    writeKeyFile(filePath, key.toString("base64"), 0o400);
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      loadMacKey({ source: "file", ref: filePath }, tmpDir);
      expect(warnSpy).not.toHaveBeenCalled();
    } finally {
      warnSpy.mockRestore();
    }
  });

  it("throws when file is missing", () => {
    expect(() =>
      loadMacKey({ source: "file", ref: "nope.key" }, tmpDir),
    ).toThrow(MacKeyLoadError);
  });

  it("throws when file is empty", () => {
    writeKeyFile(join(tmpDir, "empty"), "");
    expect(() => loadMacKey({ source: "file", ref: "empty" }, tmpDir)).toThrow(MacKeyLoadError);
  });
});

describe("loadMacKeyFromConfig", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "mavryn-key-cfg-"));
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("returns null when audit.macKey is not configured", () => {
    expect(loadMacKeyFromConfig({}, tmpDir)).toBeNull();
  });

  it("propagates MacKeyLoadError when configured but unloadable", () => {
    expect(() =>
      loadMacKeyFromConfig({ macKey: { source: "env", ref: "DEFINITELY_NOT_SET_XYZ" } }, tmpDir),
    ).toThrow(MacKeyLoadError);
  });
});
