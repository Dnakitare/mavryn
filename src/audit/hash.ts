import { createHash } from "node:crypto";
import canonicalize from "canonicalize";

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
 * SHA-256 over a positional array of event fields, serialized via RFC 8785 JCS
 * (canonical JSON). JCS pins object key ordering to lexicographic, normalizes
 * number formatting, and removes whitespace — so the byte sequence we hash is
 * identical regardless of the JS engine, the order keys were inserted in, or
 * whether arguments came from a JSON.parse round-trip.
 *
 * This is the property that lets a third-party verifier (Python, Go, an
 * auditor's tool) reproduce our hashes byte-for-byte. Without it, we'd be
 * coupling the audit-trail's tamper-evidence to V8's serialization quirks.
 */
export function computeEventHash(event: HashableEvent): string {
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
    throw new Error("computeEventHash: canonicalize returned undefined (event contains a non-JSON-serializable value)");
  }
  return createHash("sha256").update(payload).digest("hex");
}

export function verifyChain(events: HashableEvent[]): { valid: boolean; brokenAt?: number } {
  for (let i = 0; i < events.length; i++) {
    const event = events[i];
    const expectedHash = computeEventHash(event);

    if ("eventHash" in event && (event as any).eventHash !== expectedHash) {
      return { valid: false, brokenAt: i };
    }

    if (i > 0) {
      const prevEvent = events[i - 1];
      const prevHash =
        "eventHash" in prevEvent ? (prevEvent as any).eventHash : computeEventHash(prevEvent);
      if (event.prevHash !== prevHash) {
        return { valid: false, brokenAt: i };
      }
    }
  }
  return { valid: true };
}
