/**
 * Secret redaction for logs, audit trails, and error messages.
 *
 * Detects common secret patterns and replaces them with [REDACTED].
 * Applied to all data before it leaves the proxy layer — logs, audit,
 * and error messages never contain raw secrets.
 */

const SECRET_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
  // API keys and tokens (generic)
  { name: "bearer_token", pattern: /Bearer\s+[A-Za-z0-9\-._~+/]+=*/gi },
  { name: "api_key_value", pattern: /(?:api[_-]?key|apikey|api[_-]?secret|api[_-]?token)\s*[:=]\s*["']?[A-Za-z0-9\-._~+/]{16,}["']?/gi },

  // GitHub tokens
  { name: "github_pat", pattern: /gh[pousr]_[A-Za-z0-9_]{36,}/g },
  { name: "github_classic", pattern: /ghp_[A-Za-z0-9]{36,}/g },

  // AWS
  { name: "aws_access_key", pattern: /AKIA[0-9A-Z]{16}/g },
  { name: "aws_secret_key", pattern: /(?:aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}["']?/gi },

  // Generic secrets (long hex/base64 strings in key-value context)
  { name: "secret_value", pattern: /(?:secret|password|passwd|token|credential|private[_-]?key)\s*[:=]\s*["']?[^\s"',]{12,}["']?/gi },

  // JWTs
  { name: "jwt", pattern: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },

  // Private keys
  { name: "private_key", pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g },

  // Connection strings with embedded passwords
  { name: "connection_string", pattern: /:\/\/[^:]+:[^@\s]{8,}@/g },
];

/**
 * Redact secrets from a string.
 */
export function redactString(input: string): string {
  let result = input;
  for (const { pattern } of SECRET_PATTERNS) {
    // Reset lastIndex for stateful regex (global flag)
    pattern.lastIndex = 0;
    result = result.replace(pattern, "[REDACTED]");
  }
  return result;
}

/**
 * Deep-redact secrets from an arbitrary value.
 * Returns a new object with all string values scrubbed.
 * Handles circular references safely.
 */
export function redactValue(value: unknown, seen = new WeakSet<object>()): unknown {
  if (value === null || value === undefined) return value;

  if (typeof value === "string") {
    return redactString(value);
  }

  if (typeof value !== "object") return value;

  // Prevent circular reference loops
  const obj = value as object;
  if (seen.has(obj)) return "[circular]";
  seen.add(obj);

  if (Array.isArray(value)) {
    return value.map((item) => redactValue(item, seen));
  }

  const result: Record<string, unknown> = {};
  for (const [key, val] of Object.entries(value as Record<string, unknown>)) {
    // Redact entire values for known secret field names
    if (isSecretFieldName(key)) {
      result[key] = "[REDACTED]";
    } else {
      result[key] = redactValue(val, seen);
    }
  }
  return result;
}

/**
 * Redact-and-report variants: same scrubbing as redactString / redactValue,
 * but also report whether any redaction actually fired. Audit rows use the
 * boolean to set `redactions_applied` so DSAR-style queries can identify
 * rows where original content was scrubbed.
 */
export function redactStringTracked(input: string): { value: string; redacted: boolean } {
  const result = redactString(input);
  return { value: result, redacted: result !== input };
}

export function redactValueTracked(value: unknown): { value: unknown; redacted: boolean } {
  const tracker = { redacted: false };
  const result = redactValueWithTracker(value, tracker, new WeakSet<object>());
  return { value: result, redacted: tracker.redacted };
}

function redactValueWithTracker(
  value: unknown,
  tracker: { redacted: boolean },
  seen: WeakSet<object>,
): unknown {
  if (value === null || value === undefined) return value;

  if (typeof value === "string") {
    const replaced = redactString(value);
    if (replaced !== value) tracker.redacted = true;
    return replaced;
  }

  if (typeof value !== "object") return value;

  const obj = value as object;
  if (seen.has(obj)) return "[circular]";
  seen.add(obj);

  if (Array.isArray(value)) {
    return value.map((item) => redactValueWithTracker(item, tracker, seen));
  }

  const result: Record<string, unknown> = {};
  for (const [key, val] of Object.entries(value as Record<string, unknown>)) {
    if (isSecretFieldName(key)) {
      tracker.redacted = true;
      result[key] = "[REDACTED]";
    } else {
      result[key] = redactValueWithTracker(val, tracker, seen);
    }
  }
  return result;
}

const SECRET_FIELD_NAMES = new Set([
  "password", "passwd", "secret", "token", "api_key", "apikey",
  "api_secret", "apisecret", "access_token", "accesstoken",
  "refresh_token", "refreshtoken", "private_key", "privatekey",
  "client_secret", "clientsecret", "authorization",
  "x-api-key", "x-auth-token",
]);

function isSecretFieldName(name: string): boolean {
  return SECRET_FIELD_NAMES.has(name.toLowerCase().replace(/-/g, "_"));
}

/**
 * Resolve environment variable references in config values.
 * Supports $ENV_VAR and ${ENV_VAR} syntax.
 * Returns the resolved value, or throws if the env var is not set.
 */
export function resolveEnvVars(value: string): string {
  return value.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)/g, (match, braced, unbraced) => {
    const varName = braced ?? unbraced;
    const envValue = process.env[varName];
    if (envValue === undefined) {
      throw new Error(`Environment variable '${varName}' is not set (referenced in config)`);
    }
    return envValue;
  });
}

/**
 * Resolve env var references in transport config values.
 * Only resolves strings that start with $ to avoid false positives.
 */
export function resolveTransportEnv(env?: Record<string, string>): Record<string, string> | undefined {
  if (!env) return undefined;
  const resolved: Record<string, string> = {};
  for (const [key, value] of Object.entries(env)) {
    resolved[key] = value.startsWith("$") ? resolveEnvVars(value) : value;
  }
  return resolved;
}

/**
 * Check response content size and truncate if too large.
 * Prevents upstream servers from returning massive payloads.
 */
const MAX_CONTENT_SIZE = 10 * 1024 * 1024; // 10MB

export function enforceContentLimit(content: unknown[]): unknown[] {
  let totalSize = 0;
  const limited: unknown[] = [];

  for (const item of content) {
    const itemSize = estimateSize(item);
    if (totalSize + itemSize > MAX_CONTENT_SIZE) {
      limited.push({
        type: "text",
        text: `[Mavryn: response truncated — exceeded ${MAX_CONTENT_SIZE / 1024 / 1024}MB limit]`,
      });
      break;
    }
    totalSize += itemSize;
    limited.push(item);
  }

  return limited;
}

function estimateSize(value: unknown): number {
  if (typeof value === "string") return value.length;
  if (typeof value !== "object" || value === null) return 8;
  try {
    return JSON.stringify(value).length;
  } catch {
    return MAX_CONTENT_SIZE; // Treat unserializable as max to be safe
  }
}
