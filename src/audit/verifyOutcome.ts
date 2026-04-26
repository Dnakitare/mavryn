/**
 * Pure terminal-state formatter for `mavryn audit verify`. Given the final
 * counts after streaming the chain (with no in-loop failures), produce the
 * exit code and human-readable lines.
 *
 * In-loop failures (hash mismatch, prev_hash mismatch, MAC mismatch with key,
 * monotonicity violation) exit 1 directly with their own error messages —
 * they don't reach this function. This function only handles the "chain
 * walked cleanly, what does the end-state mean?" cases.
 */
export interface VerifyTerminalState {
  count: number;
  macKeyConfigured: boolean;
  macVerified: number;
  hashOnlyRows: number;
  macSkippedNoKey: number;
  /** From audit_meta. Null if no MAC'd row has ever been written, OR the watermark was tampered. */
  firstMacSeq: number | null;
}

export interface VerifyTerminalOutcome {
  exitCode: 0 | 1;
  lines: string[];
}

export function formatVerifyTerminal(s: VerifyTerminalState): VerifyTerminalOutcome {
  if (s.count === 0) {
    return { exitCode: 0, lines: ["No audit entries to verify."] };
  }

  if (s.macKeyConfigured) {
    // No watermark, but rows have MACs → audit_meta was tampered. Distinct
    // from cold-start because cold-start has zero MAC'd rows.
    if (s.firstMacSeq === null && s.macVerified > 0) {
      return {
        exitCode: 1,
        lines: [
          `✗ audit_meta.first_mac_seq is missing but ${s.macVerified} rows have MACs.`,
          `  audit_meta was tampered or deleted. Without the watermark we cannot enforce`,
          `  the "every row after the first MAC'd row must also be MAC'd" invariant —`,
          `  meaning rows could have been laundered by stripping their event_mac.`,
        ],
      };
    }

    // No watermark and no MAC'd rows. Indistinguishable from {cold start
    // before first MAC'd write} vs {attacker stripped MACs and deleted
    // watermark}. Soft-fail: exit 1 with a warning. Cold-start users see
    // this once and clear it with a single tool call.
    if (s.firstMacSeq === null && s.macVerified === 0) {
      return {
        exitCode: 1,
        lines: [
          `⚠ ${s.count} events verified — chain intact, but no rows have MACs and audit_meta is empty.`,
          `  Either audit.macKey was just enabled and no tool calls have happened yet,`,
          `  or both MACs and the watermark were stripped (operator-tamper attempt).`,
          `  Run a tool call to write a MAC'd row, then re-verify.`,
        ],
      };
    }

    // Watermark present + chain walked clean → monotonicity already enforced
    // in-loop. Differentiate based on whether the DB straddles the watermark.
    const hashOnlyBeforeWatermark = s.hashOnlyRows;
    if (hashOnlyBeforeWatermark === 0) {
      return {
        exitCode: 0,
        lines: [`✓ ${s.count} events verified — chain intact, ${s.macVerified} MAC-verified`],
      };
    }
    return {
      exitCode: 0,
      lines: [
        `✓ ${s.count} events verified — chain intact (${s.macVerified} MAC-verified, ${hashOnlyBeforeWatermark} legacy hash-only)`,
        `  Hash-only rows predate audit.macKey configuration (first MAC at seq=${s.firstMacSeq}).`,
      ],
    };
  }

  // macKey not configured.
  if (s.macSkippedNoKey > 0) {
    return {
      exitCode: 0,
      lines: [
        `⚠ ${s.count} events verified — chain intact, but ${s.macSkippedNoKey} rows have MACs that were not checked`,
        `  audit.macKey is not configured. Configure it in mavryn.config.json to verify MACs.`,
      ],
    };
  }
  return {
    exitCode: 0,
    lines: [`✓ ${s.count} events verified — chain intact (hash-only; no audit.macKey configured)`],
  };
}
