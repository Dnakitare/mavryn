#!/usr/bin/env python3
"""
mavryn_verify.py - reference verifier for Mavryn audit chains (v0.5+).

Single-file, Python-stdlib-only. Validates the SHA-256 hash chain and
(optionally) the HMAC-SHA256 keyed MACs over RFC 8785 JCS canonical JSON,
the same way the Mavryn TypeScript implementation does. This is the
"third-party verifier" referenced in Mavryn's threat model: an auditor can
copy the audit DB off the host and verify cryptographic integrity without
trusting any binary from the Mavryn build.

USAGE
    python3 mavryn_verify.py --db audit.db
    python3 mavryn_verify.py --db audit.db --key-base64 'BASE64KEY=='
    python3 mavryn_verify.py --db audit.db --key-file /path/to/key

EXIT CODES
    0 - chain intact (and MACs verified, if a key was provided)
    1 - chain broken, MAC mismatch, monotonicity violation, watermark
        tampered, or cold-start with key supplied (indistinguishable from
        full-strip attack)

WHAT THIS CHECKS
    1. Every row's event_hash matches SHA-256 of its canonical payload.
    2. Every row's prev_hash matches the previous row's event_hash.
    3. If a key is provided: every row's event_mac matches HMAC-SHA256 of
       the canonical payload.
    4. Monotonicity: every row at seq >= audit_meta.first_mac_seq must
       have a non-NULL event_mac.
    5. Watermark consistency: if any row has event_mac, audit_meta.first_mac_seq
       must be set.

LIMITATION (numeric canonicalization)
    JCS specifies ECMAScript Number -> String conversion. This verifier
    uses Python's json.dumps, which matches ES Number for integers and
    "nice" floats but diverges for edge cases (1.0 vs 1, large floats with
    exponents, -0). Typical Mavryn audit content - strings, ISO timestamps,
    integer arguments - produces byte-for-byte identical canonical bytes.
    If your audit rows contain edge-case floats, install the `jcs` PyPI
    package and replace _canonicalize() with jcs.canonicalize().
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import re
import sqlite3
import sys
from dataclasses import dataclass
from typing import Any, Iterable


REQUIRED_KEY_BYTES = 32

BASE64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")


def _canonicalize(value: Any) -> bytes:
    """RFC 8785 JCS canonical JSON, stdlib-only. See module docstring on
    numeric edge cases."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _row_payload(row: sqlite3.Row) -> list[Any]:
    """Reconstruct the positional canonical-payload array from a SQLite row.

    Mirrors the field order in src/audit/hash.ts canonicalPayload(). JSON
    string columns (tool_arguments, tool_annotations, policies_evaluated,
    meta) are parsed back into objects/arrays. redactions_applied is
    converted INTEGER 0/1 -> bool. NULL columns become None.
    """
    def parsed(col: str) -> Any:
        v = row[col]
        return None if v is None else json.loads(v)

    policies = parsed("policies_evaluated")
    return [
        row["id"],
        row["timestamp"],
        row["session_id"],
        row["server_name"],
        row["agent_id"],
        row["tool_name"],
        parsed("tool_arguments"),
        parsed("tool_annotations"),
        row["policy_decision"],
        policies if policies is not None else [],
        row["result_status"],
        row["user_id"],
        row["source_tag"],
        row["prompt_context"],
        row["turn_id"],
        row["assistant_message"],
        row["system_prompt_hash"],
        parsed("meta"),
        bool(row["redactions_applied"]),
        row["prev_hash"],
    ]


def _compute_event_hash(payload: list[Any]) -> str:
    return hashlib.sha256(_canonicalize(payload)).hexdigest()


def _compute_event_mac(payload: list[Any], key: bytes) -> str:
    return hmac.new(key, _canonicalize(payload), hashlib.sha256).hexdigest()


def _try_get(row: sqlite3.Row, col: str) -> Any:
    """Tolerant column access - pre-v0.5 schemas don't have event_mac etc."""
    try:
        return row[col]
    except (IndexError, KeyError):
        return None


@dataclass
class VerifyResult:
    ok: bool
    count: int
    mac_verified: int
    legacy_hash_only: int
    mac_skipped_no_key: int
    first_mac_seq: int | None
    error: str | None = None


def verify(db_path: str, key: bytes | None) -> VerifyResult:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        first_mac_seq: int | None = None
        try:
            r = conn.execute(
                "SELECT value FROM audit_meta WHERE key = 'first_mac_seq'"
            ).fetchone()
            if r is not None:
                try:
                    first_mac_seq = int(r["value"])
                except (TypeError, ValueError):
                    pass
        except sqlite3.OperationalError:
            # Pre-v0.5 schema - no audit_meta table.
            pass

        prev_hash: str | None = None
        count = 0
        mac_verified = 0
        legacy_hash_only = 0
        mac_skipped_no_key = 0

        for row in conn.execute("SELECT * FROM events ORDER BY seq ASC"):
            seq = row["seq"]
            ref = f"seq={seq} id={row['id']}"
            payload = _row_payload(row)

            expected_hash = _compute_event_hash(payload)
            if expected_hash != row["event_hash"]:
                return VerifyResult(
                    ok=False,
                    count=count,
                    mac_verified=mac_verified,
                    legacy_hash_only=legacy_hash_only,
                    mac_skipped_no_key=mac_skipped_no_key,
                    first_mac_seq=first_mac_seq,
                    error=(
                        f"chain broken at {ref}: event_hash mismatch "
                        f"(expected {expected_hash}, stored {row['event_hash']})"
                    ),
                )

            if row["prev_hash"] != prev_hash:
                return VerifyResult(
                    ok=False,
                    count=count,
                    mac_verified=mac_verified,
                    legacy_hash_only=legacy_hash_only,
                    mac_skipped_no_key=mac_skipped_no_key,
                    first_mac_seq=first_mac_seq,
                    error=(
                        f"chain broken at {ref}: prev_hash mismatch "
                        f"(expected {prev_hash!r}, stored {row['prev_hash']!r})"
                    ),
                )

            stored_mac = _try_get(row, "event_mac")

            if (
                key is not None
                and first_mac_seq is not None
                and seq is not None
                and seq >= first_mac_seq
                and stored_mac is None
            ):
                return VerifyResult(
                    ok=False,
                    count=count,
                    mac_verified=mac_verified,
                    legacy_hash_only=legacy_hash_only,
                    mac_skipped_no_key=mac_skipped_no_key,
                    first_mac_seq=first_mac_seq,
                    error=(
                        f"MAC monotonicity violated at {ref}: row has no event_mac "
                        f"but audit_meta.first_mac_seq={first_mac_seq}"
                    ),
                )

            if stored_mac is not None:
                if key is not None:
                    expected_mac = _compute_event_mac(payload, key)
                    if not hmac.compare_digest(stored_mac, expected_mac):
                        return VerifyResult(
                            ok=False,
                            count=count,
                            mac_verified=mac_verified,
                            legacy_hash_only=legacy_hash_only,
                            mac_skipped_no_key=mac_skipped_no_key,
                            first_mac_seq=first_mac_seq,
                            error=(
                                f"MAC verification failed at {ref}: "
                                f"expected {expected_mac}, stored {stored_mac}. "
                                f"Likely cause: row was modified by someone without "
                                f"the key, OR the wrong key was supplied."
                            ),
                        )
                    mac_verified += 1
                else:
                    mac_skipped_no_key += 1
            else:
                legacy_hash_only += 1

            prev_hash = row["event_hash"]
            count += 1

        if key is not None and first_mac_seq is None and mac_verified > 0:
            return VerifyResult(
                ok=False,
                count=count,
                mac_verified=mac_verified,
                legacy_hash_only=legacy_hash_only,
                mac_skipped_no_key=mac_skipped_no_key,
                first_mac_seq=None,
                error=(
                    f"audit_meta.first_mac_seq is missing but {mac_verified} rows have "
                    f"MACs. The watermark was deleted (operator-tamper attempt)."
                ),
            )

        return VerifyResult(
            ok=True,
            count=count,
            mac_verified=mac_verified,
            legacy_hash_only=legacy_hash_only,
            mac_skipped_no_key=mac_skipped_no_key,
            first_mac_seq=first_mac_seq,
        )
    finally:
        conn.close()


def _load_key_from_args(args: argparse.Namespace) -> bytes | None:
    if args.key_base64 is None and args.key_file is None:
        return None
    if args.key_base64 is not None and args.key_file is not None:
        sys.exit("error: pass at most one of --key-base64 / --key-file")

    if args.key_base64 is not None:
        raw = args.key_base64.strip()
    else:
        with open(args.key_file, "r", encoding="utf-8") as f:
            raw = f.read().strip()

    if not raw:
        sys.exit("error: key value is empty")

    if not BASE64_RE.match(raw):
        sys.exit("error: key contains non-base64 characters")

    try:
        decoded = base64.b64decode(raw, validate=True)
    except Exception as e:
        sys.exit(f"error: key is not valid base64: {e}")

    if len(decoded) != REQUIRED_KEY_BYTES:
        sys.exit(
            f"error: key must decode to {REQUIRED_KEY_BYTES} bytes, got {len(decoded)}"
        )

    return decoded


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mavryn_verify",
        description=(
            "Reference verifier for Mavryn audit chains. Validates SHA-256 hash "
            "chain and (optionally) HMAC-SHA256 keyed MACs."
        ),
    )
    parser.add_argument("--db", required=True, help="Path to the audit SQLite DB")
    parser.add_argument(
        "--key-base64",
        help="audit.macKey value (base64). 32 bytes after decode.",
    )
    parser.add_argument(
        "--key-file",
        help="Path to a file containing the base64-encoded key.",
    )
    args = parser.parse_args(argv)

    key = _load_key_from_args(args)
    result = verify(args.db, key)

    if not result.ok:
        print(f"x {result.error}", file=sys.stderr)
        return 1

    if result.count == 0:
        print("No audit entries to verify.")
        return 0

    if key is not None:
        if result.first_mac_seq is not None:
            if result.legacy_hash_only == 0:
                print(
                    f"OK {result.count} events verified - chain intact, "
                    f"{result.mac_verified} MAC-verified"
                )
            else:
                print(
                    f"OK {result.count} events verified - chain intact "
                    f"({result.mac_verified} MAC-verified, "
                    f"{result.legacy_hash_only} legacy hash-only). "
                    f"First MAC at seq={result.first_mac_seq}."
                )
            return 0
        else:
            # Key supplied but no MAC'd rows and no watermark. Ambiguous:
            # cold start vs full strip. Match the TS verifier - exit 1.
            print(
                f"WARN {result.count} events verified - chain intact, but no rows "
                f"have MACs and audit_meta is empty. Either macKey was just enabled "
                f"and no tool calls have happened yet, or both MACs and the watermark "
                f"were stripped (operator-tamper attempt).",
                file=sys.stderr,
            )
            return 1
    else:
        if result.mac_skipped_no_key > 0:
            print(
                f"WARN {result.count} events verified - chain intact, but "
                f"{result.mac_skipped_no_key} rows have MACs that were not checked "
                f"(no key supplied)."
            )
        else:
            print(
                f"OK {result.count} events verified - chain intact "
                f"(hash-only; no key supplied)"
            )
        return 0


if __name__ == "__main__":
    sys.exit(main())
