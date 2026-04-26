# Mavryn audit verifier (Python reference)

A standalone, stdlib-only Python implementation of Mavryn's audit-chain verification logic. Intended for third-party auditors or anyone who wants to verify a Mavryn audit DB without running the Mavryn binary.

## Why this exists

Mavryn's TypeScript implementation hashes audit rows as `SHA-256(JCS(canonicalPayload))` and (when `audit.macKey` is configured) MACs them as `HMAC-SHA256(key, JCS(canonicalPayload))`. JCS (RFC 8785) is canonical JSON — same input bytes regardless of language. That means a Python or Go implementation can reproduce the hashes byte-for-byte.

This file is the proof. The vitest suite at `src/audit/__tests__/pythonVerifier.test.ts` cross-checks it against the TS implementation on every `npm test` run.

## Usage

```bash
# Hash chain only (no MAC verification)
python3 mavryn_verify.py --db /path/to/audit.db

# With key, from a base64 string
python3 mavryn_verify.py --db /path/to/audit.db \
    --key-base64 'BASE64KEY=='

# With key, from a file
python3 mavryn_verify.py --db /path/to/audit.db \
    --key-file /path/to/audit.key
```

Exit codes: `0` on full success, `1` on chain break / MAC mismatch / monotonicity violation / watermark tampering / cold-start-with-key (indistinguishable from full-strip attack).

## What it checks

1. Every row's `event_hash` matches `SHA-256` over its canonical payload.
2. Every row's `prev_hash` matches the previous row's `event_hash` (chain integrity).
3. **With `--key-*`:** every row's `event_mac` matches `HMAC-SHA256(key, canonical payload)`.
4. **Monotonicity:** every row at `seq >= audit_meta.first_mac_seq` must have a non-NULL `event_mac`. (Closes the laundering vector where an attacker would `UPDATE events SET event_mac=NULL`.)
5. **Watermark consistency:** if any row has `event_mac` but `audit_meta.first_mac_seq` is missing, the watermark was deleted — a known operator-tamper attempt.

## Limitations

JCS specifies ECMAScript Number → String for numeric values. This verifier uses Python's `json.dumps`, which matches ES Number for integers and "nice" floats but diverges for edge cases (e.g. `1.0` vs `1`, large floats with exponents, `-0`). For typical Mavryn audit content — strings, ISO timestamps, integer arguments — the canonical bytes are byte-for-byte identical to the TS implementation.

If your audit rows contain JS Number values that fall in an edge case, install the [`jcs`](https://pypi.org/project/jcs/) PyPI package and replace `_canonicalize()` with `jcs.canonicalize()`.

## Dependencies

Python 3.10+ standard library only:
- `sqlite3`
- `hashlib`
- `hmac`
- `json`
- `base64`
- `argparse`
