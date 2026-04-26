# Changelog

All notable changes to Mavryn are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows [SemVer](https://semver.org/spec/v2.0.0.html).

## [0.5.0]

### Added

- **Operator-tamper defense for the audit chain (HMAC-SHA256).** When `audit.macKey` is configured, every new row is keyed-MAC'd over the same RFC 8785 JCS canonical payload as `event_hash`. An attacker with DB write access but no key cannot forge MACs, so any rewrite is detected by `mavryn audit verify`. Opt-in by config; behavior is unchanged from 0.3.x when `macKey` is unset.
- **Key sources:** `audit.macKey: { source: "env" | "file", ref: <env-var-name | path> }`. Keys are 32 bytes, base64-encoded. Strict validation rejects typos that would silently decode to garbage. KMS/Vault/HSM sources are reserved for 0.6+.
- **Monotonicity invariant via `audit_meta.first_mac_seq`.** Tracks the seq of the first MAC'd row; verify enforces "every row at `seq >= first_mac_seq` must be MAC'd," closing the laundering vector where an attacker would `UPDATE events SET event_mac=NULL` to bypass MAC checks.
- **Schema columns reserved for v0.6 external anchoring:** `anchor_hash`, `anchor_seq`, `anchor_source` (all NULL in 0.5).
- **`mavryn audit verify` upgrades:** four-case outcome reporting (full MACs, mixed boundary, watermark-tampered, cold-start), constant-time MAC compare via `crypto.timingSafeEqual`, error messages branched on whether prior rows passed (misconfig vs tampering).
- **Hard-fail at startup on misconfigured `macKey`** (env var unset, file missing, key wrong length, non-base64 characters). `mavryn serve` and `mavryn audit verify` exit non-zero with a specific reason rather than silently no-op'ing.
- **File-mode warning** when `source: file` and the key file is group/world-readable.
- **`mavryn init` scaffolds the macKey on-ramp** in its post-init hint output.
- **Python reference verifier** at `verifier/mavryn_verify.py` — single-file, stdlib-only, demonstrates JCS+HMAC reproducibility for third-party auditors.
- **CSV export** now includes `event_mac`, `anchor_hash`, `anchor_seq`, `anchor_source` columns (was silently dropping them).

### Changed

- **Schema migration to user_version=2.** Wrapped in a single transaction; partial failure rolls back cleanly. Inline-only (no separate .sql files).
- **Verify exit semantics:** when `audit.macKey` is configured but no MAC'd rows exist (cold start OR full strip), exit code is now 1 with a warning. The state is indistinguishable from a tampering attempt; this is by design. Resolve cold-start by writing one row (any tool call) and re-running verify.
- **Verify description and threat-model wording** clarified to distinguish "without write access" from "with write access but no key."
- **`SqliteAuditStore.append()`** now refuses rows without `eventMac` when the store has a `macKey` configured. (Previously test-only API; closing the public-interface footgun.)
- **README** rewritten around v0.5: "Operator-tamper defense" subsection, explicit disclosure of what HMAC alone does *not* defend against (operator+key, truncation, snapshot rollback), key rotation guidance, four upgrade scenarios.

### Security

- **Strict base64 charset validation in `keyLoader`.** `Buffer.from(str, "base64")` silently drops non-base64 characters and can produce a coincidentally-32-byte derived garbage key from a typo'd input (smart quotes, stray whitespace, copy-paste artifacts). The new regex pre-check (`/^[A-Za-z0-9+/]+={0,2}$/`) rejects these explicitly. Without this, a user with a typo'd key would have a "working" Mavryn with no actual operator-tamper defense.
- **Constant-time MAC comparison** via `crypto.timingSafeEqual`. Verify is offline so the threat model is mostly absent here, but it's a standard compliance-audit checkbox at no real cost.

### Migration notes

- **Forward (0.3.x → 0.5):** Schema migration runs automatically. Pre-existing rows are preserved with `event_mac` NULL; they verify as legacy hash-only.
- **Backward (0.5 → 0.3.x):** Not supported — older builds happily open a 0.5 DB (no `user_version` check, new columns are nullable) and silently write rows without MACs alongside MAC'd ones. Take a backup with `mavryn audit backup audit-pre-v05.db` before upgrading if rollback is a possibility.
- **Key rotation:** Not supported in 0.5. Rotating `audit.macKey` makes pre-rotation MACs unverifiable. Re-MACing existing rows would forge a false attestation, so it is deliberately not offered. See README → "Key rotation" for the recommended workflow.

### Threat model (what 0.5 does NOT defend against)

- An operator with both DB write access AND the same key.
- Truncation (`DELETE FROM events WHERE seq > N`) — the chain proves rows are unaltered, not that no rows were removed off the end.
- Snapshot rollback — restoring a backup, then writing on top, is invisible to the in-DB chain.

All three are addressed by 0.6 external anchoring. The schema and the README already account for that.

## Prior history

Pre-0.5 releases (0.2.x, 0.3.x) are documented in git history. Headline: 0.2.0 ported `@imara/store`'s hash-chained SQLite audit into Mavryn; 0.3.0/0.3.1 hardened correctness (RFC 8785 JCS canonical hashing, multi-process safety, fail-closed mode, per-call attribution).

[0.5.0]: https://github.com/Dnakitare/mavryn/releases/tag/v0.5.0
