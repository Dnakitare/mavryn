import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import canonicalize from "canonicalize";

/**
 * Constant-time hex-string compare. Returns false on any length mismatch
 * (including invalid hex input). Used for MAC compares; not strictly
 * required for this offline threat model, but standard practice in
 * compliance audits and a one-line correction so it costs nothing.
 */
export function safeHexEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let bufA: Buffer;
  let bufB: Buffer;
  try {
    bufA = Buffer.from(a, "hex");
    bufB = Buffer.from(b, "hex");
  } catch {
    return false;
  }
  if (bufA.length !== bufB.length || bufA.length === 0) return false;
  return timingSafeEqual(bufA, bufB);
}

export interface HashableEvent {
  id: string;
  timestamp: string;
  sessionId: string;
  serverName: string;
  agentId?: string;
  toolName: string;
  toolArguments: Record<string, unknown>;
  toolAnnotations?: Record<string, unknown>;
  policyDecision: string;
  policiesEvaluated?: string[];
  resultStatus?: string;
  userId?: string;
  sourceTag?: string;
  promptContext?: string;
  turnId?: string;
  assistantMessage?: string;
  systemPromptHash?: string;
  meta?: Record<string, unknown>;
  redactionsApplied?: boolean;
  prevHash: string | null;
}

/**
 * RFC 8785 JCS canonical JSON over a positional array of event fields. Pinned
 * key ordering, normalized number formatting, no whitespace — the byte
 * sequence is identical regardless of the JS engine, key insertion order, or
 * JSON.parse round-trips. Lets a third-party verifier (Python, Go, an
 * auditor's tool) reproduce our hashes byte-for-byte.
 *
 * Both event_hash (SHA-256) and event_mac (HMAC-SHA256) share this payload
 * by design: a verifier with the key checks both; without the key, falls
 * back to event_hash.
 */
function canonicalPayload(event: HashableEvent): string {
  const payload = canonicalize([
    event.id,
    event.timestamp,
    event.sessionId,
    event.serverName,
    event.agentId ?? null,
    event.toolName,
    event.toolArguments,
    event.toolAnnotations ?? null,
    event.policyDecision,
    event.policiesEvaluated ?? [],
    event.resultStatus ?? null,
    event.userId ?? null,
    event.sourceTag ?? null,
    event.promptContext ?? null,
    event.turnId ?? null,
    event.assistantMessage ?? null,
    event.systemPromptHash ?? null,
    event.meta ?? null,
    event.redactionsApplied ?? false,
    event.prevHash,
  ]);
  if (payload === undefined) {
    throw new Error("canonicalPayload: canonicalize returned undefined (event contains a non-JSON-serializable value)");
  }
  return payload;
}

export function computeEventHash(event: HashableEvent): string {
  return createHash("sha256").update(canonicalPayload(event)).digest("hex");
}

/**
 * HMAC-SHA256 keyed authenticator over the same canonical payload as
 * computeEventHash. An attacker with DB write access but no key cannot forge
 * this — even if they recompute event_hash, event_mac will mismatch and
 * `mavryn audit verify` (with key) will fail. This is the operator-tamper
 * defense; the unkeyed event_hash remains for cross-runtime portability.
 */
export function computeEventMac(event: HashableEvent, key: Buffer): string {
  if (key.length === 0) {
    throw new Error("computeEventMac: key must not be empty");
  }
  return createHmac("sha256", key).update(canonicalPayload(event)).digest("hex");
}

export function verifyChain(
  events: HashableEvent[],
  opts?: { key?: Buffer | null },
): { valid: boolean; brokenAt?: number; reason?: string } {
  const key = opts?.key ?? null;

  for (let i = 0; i < events.length; i++) {
    const event = events[i];
    const expectedHash = computeEventHash(event);

    if ("eventHash" in event && (event as any).eventHash !== expectedHash) {
      return { valid: false, brokenAt: i, reason: "event_hash mismatch" };
    }

    if (i > 0) {
      const prevEvent = events[i - 1];
      const prevHash =
        "eventHash" in prevEvent ? (prevEvent as any).eventHash : computeEventHash(prevEvent);
      if (event.prevHash !== prevHash) {
        return { valid: false, brokenAt: i, reason: "prev_hash mismatch" };
      }
    }

    // `"eventMac" in event` was previously also checked here, but rowToEvent
    // always sets the property (to undefined or a hex string), so the `in`
    // operator never gates anything for store-loaded events. The `stored !=
    // null` guard handles undefined; that's the real check. Monotonicity
    // (every row after first_mac_seq must have a MAC) is enforced one level
    // up in the CLI verify command, where the watermark is available.
    if (key) {
      const stored = (event as any).eventMac as string | null | undefined;
      if (stored != null) {
        const expectedMac = computeEventMac(event, key);
        if (!safeHexEqual(stored, expectedMac)) {
          return { valid: false, brokenAt: i, reason: "event_mac mismatch" };
        }
      }
    }
  }
  return { valid: true };
}
