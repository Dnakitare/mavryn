import { readFileSync, statSync } from "node:fs";
import path from "node:path";

export interface MacKeyConfig {
  source: "env" | "file";
  ref: string;
}

export class MacKeyLoadError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MacKeyLoadError";
  }
}

const REQUIRED_KEY_BYTES = 32;

/**
 * Load and validate the HMAC key from the configured source. Throws
 * MacKeyLoadError with a specific reason on any failure — intended to bubble
 * up to server startup so misconfiguration is loud, not silent.
 *
 * configDir is used to resolve relative file paths (consistent with how
 * audit.file is resolved).
 */
export function loadMacKey(config: MacKeyConfig, configDir: string): Buffer {
  let raw: string;

  if (config.source === "env") {
    const value = process.env[config.ref];
    if (value === undefined) {
      throw new MacKeyLoadError(
        `audit.macKey.source=env but environment variable ${config.ref} is not set`,
      );
    }
    raw = value.trim();
    if (raw.length === 0) {
      throw new MacKeyLoadError(
        `audit.macKey.source=env but environment variable ${config.ref} is empty`,
      );
    }
  } else {
    const filePath = path.isAbsolute(config.ref)
      ? config.ref
      : path.resolve(configDir, config.ref);
    try {
      raw = readFileSync(filePath, "utf-8").trim();
    } catch (err) {
      throw new MacKeyLoadError(
        `audit.macKey.source=file but couldn't read ${filePath}: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
    if (raw.length === 0) {
      throw new MacKeyLoadError(`audit.macKey.source=file but ${filePath} is empty`);
    }

    // World/group readability is the most common ops mistake. Warn (not
    // fail) — file mode semantics differ across mounted secret stores
    // (k8s projected volumes, systemd LoadCredential, fuse-mounted KMS),
    // and a hard fail would block legitimate setups.
    try {
      const mode = statSync(filePath).mode;
      if ((mode & 0o077) !== 0) {
        const octal = (mode & 0o777).toString(8).padStart(3, "0");
        // eslint-disable-next-line no-console
        console.warn(
          `warning: audit.macKey file ${filePath} has mode ${octal}; expected 0400 (owner-read-only). ` +
            `Anyone who can read this file can forge MACs.`,
        );
      }
    } catch {
      // statSync failure on a path that already readFileSync'd is implausible;
      // if it does happen, skip the warning rather than fail.
    }
  }

  // Buffer.from(str, 'base64') silently drops non-base64 characters and can
  // produce a coincidentally-32-byte garbage key from a typo'd input
  // (smart-quote, stray '!', etc.). Validate the charset explicitly before
  // decoding — otherwise verify reports ✓ against itself with a derived
  // garbage key and the operator-tamper defense is silently disabled.
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(raw)) {
    throw new MacKeyLoadError(
      `audit.macKey value contains non-base64 characters. ` +
        `Generate a fresh key with: openssl rand -base64 32`,
    );
  }

  const decoded = Buffer.from(raw, "base64");

  if (decoded.length !== REQUIRED_KEY_BYTES) {
    throw new MacKeyLoadError(
      `audit.macKey must decode to ${REQUIRED_KEY_BYTES} bytes, got ${decoded.length}. ` +
        `Generate a fresh key with: openssl rand -base64 32`,
    );
  }

  return decoded;
}

/**
 * Convenience wrapper for callers that already have a parsed MavrynConfig.
 * Returns null when audit.macKey is unset (opt-in default). Throws
 * MacKeyLoadError when audit.macKey IS set but the key can't be loaded —
 * misconfiguration is loud, not silent.
 */
export function loadMacKeyFromConfig(
  audit: { macKey?: MacKeyConfig },
  configDir: string,
): Buffer | null {
  if (!audit.macKey) return null;
  return loadMacKey(audit.macKey, configDir);
}

