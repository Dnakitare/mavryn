import { describe, it, expect } from "vitest";
import { formatVerifyTerminal, type VerifyTerminalState } from "../verifyOutcome.js";

function state(overrides: Partial<VerifyTerminalState> = {}): VerifyTerminalState {
  return {
    count: 0,
    macKeyConfigured: false,
    macVerified: 0,
    hashOnlyRows: 0,
    macSkippedNoKey: 0,
    firstMacSeq: null,
    ...overrides,
  };
}

describe("formatVerifyTerminal", () => {
  it("count=0 → ok with empty-DB message regardless of key state", () => {
    const a = formatVerifyTerminal(state({ count: 0 }));
    expect(a.exitCode).toBe(0);
    expect(a.lines.join("\n")).toMatch(/No audit entries/);

    const b = formatVerifyTerminal(state({ count: 0, macKeyConfigured: true }));
    expect(b.exitCode).toBe(0);
  });

  it("no key configured, no MACs in DB → ok hash-only", () => {
    const o = formatVerifyTerminal(state({ count: 5, hashOnlyRows: 5 }));
    expect(o.exitCode).toBe(0);
    expect(o.lines[0]).toMatch(/hash-only; no audit\.macKey configured/);
  });

  it("no key configured, MACs present in DB → warn but exit 0 (advisory)", () => {
    const o = formatVerifyTerminal(state({ count: 5, hashOnlyRows: 0, macSkippedNoKey: 5 }));
    expect(o.exitCode).toBe(0);
    expect(o.lines[0]).toMatch(/⚠/);
    expect(o.lines[0]).toMatch(/5 rows have MACs that were not checked/);
  });

  it("key configured, watermark set, all MACs verified → ok success", () => {
    const o = formatVerifyTerminal(
      state({ count: 5, macKeyConfigured: true, macVerified: 5, firstMacSeq: 1 }),
    );
    expect(o.exitCode).toBe(0);
    expect(o.lines[0]).toMatch(/5 events verified — chain intact, 5 MAC-verified/);
    expect(o.lines).toHaveLength(1);
  });

  it("key configured, watermark set, mixed legacy hash-only + MAC'd rows → ok with boundary message", () => {
    const o = formatVerifyTerminal(
      state({
        count: 10,
        macKeyConfigured: true,
        macVerified: 6,
        hashOnlyRows: 4,
        firstMacSeq: 5,
      }),
    );
    expect(o.exitCode).toBe(0);
    expect(o.lines[0]).toMatch(/6 MAC-verified, 4 legacy hash-only/);
    expect(o.lines[1]).toMatch(/predate audit\.macKey configuration/);
    expect(o.lines[1]).toMatch(/first MAC at seq=5/);
  });

  it("key configured, watermark MISSING but MACs present → fail (audit_meta tampered)", () => {
    // This is the laundering attempt: attacker DELETE'd from audit_meta but
    // couldn't strip every event_mac. Must exit non-zero.
    const o = formatVerifyTerminal(
      state({
        count: 5,
        macKeyConfigured: true,
        macVerified: 3,
        hashOnlyRows: 2,
        firstMacSeq: null,
      }),
    );
    expect(o.exitCode).toBe(1);
    expect(o.lines[0]).toMatch(/✗/);
    expect(o.lines[0]).toMatch(/audit_meta\.first_mac_seq is missing/);
  });

  it("key configured, watermark missing AND no MACs → warn+exit1 (cold-start or full strip)", () => {
    // Indistinguishable case. Reviewer's recommendation: do not exit 0 with a
    // friendly explanation, because a full-strip attack looks identical.
    const o = formatVerifyTerminal(
      state({
        count: 5,
        macKeyConfigured: true,
        macVerified: 0,
        hashOnlyRows: 5,
        firstMacSeq: null,
      }),
    );
    expect(o.exitCode).toBe(1);
    expect(o.lines[0]).toMatch(/⚠/);
    expect(o.lines[0]).toMatch(/no rows have MACs and audit_meta is empty/);
  });
});
