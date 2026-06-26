# Mavryn

The MCP control plane — one server to route them all.

Mavryn is a single MCP server that proxies multiple upstream MCP servers. Instead of configuring 15 servers in your AI tool, you configure one: Mavryn. It handles discovery, namespacing, routing, policy enforcement, and observability.

**Mavryn and Imara.** Mavryn is the gateway: it puts many MCP servers behind a single endpoint, with namespacing, tool search, and routing. [Imara](https://github.com/Dnakitare/imara) is the governance layer that sits in front of any one server and decides, per tool call, whether it is allowed, denied, rate-limited, or escalated, then records the decision to a hash-chained audit log. Use Mavryn to consolidate, Imara to govern. They compose.

## Why

- **Tool sprawl**: 15 MCP servers = 200+ tools dumped into every prompt, wasting tokens and confusing models
- **No visibility**: No centralized logging of which tools get called, when, or by whom
- **No control**: No way to filter, restrict, or govern tool access across servers

Mavryn fixes all three.

## Quick Start

```bash
npm install -g mavryn

# Initialize a config
mavryn init

# Add upstream MCP servers
mavryn add github --stdio "npx" --args "-y" "@modelcontextprotocol/server-github"
mavryn add filesystem --stdio "npx" --args "-y" "@modelcontextprotocol/server-filesystem" "/home"
mavryn add slack --stdio "npx" --args "-y" "@modelcontextprotocol/server-slack" --tags comms

# See what's registered
mavryn list

# Start the gateway
mavryn serve
```

Then configure your AI tool to use Mavryn as its single MCP server:

```json
{
  "mcpServers": {
    "mavryn": {
      "command": "mavryn",
      "args": ["serve"]
    }
  }
}
```

That's it. All upstream tools are available, namespaced as `servername__toolname`.

## Features

### Tool Namespacing

Every upstream tool is exposed with a clear namespace:

```
github__create_issue
github__list_repos
filesystem__read_file
filesystem__write_file
slack__send_message
```

No collisions. No ambiguity.

### Built-in Search

Mavryn exposes a `mavryn_search` meta-tool that lets LLMs search across all available tools:

```
mavryn_search({ query: "read a file" })
→ 1. filesystem__read_text_file (score: 42.3)
  2. filesystem__read_file (score: 38.1)
  3. filesystem__read_multiple_files (score: 15.7)
```

Uses TF-IDF scoring with exact match boosting — no external API calls needed.

### Gateway Status

The `mavryn_status` meta-tool shows connected servers, health, and tool counts at a glance.

### Filters

Control which tools are exposed:

```json
{
  "filters": {
    "includeTags": ["dev"],
    "excludeTools": ["*__delete_*", "*__drop_*"]
  }
}
```

### Policies

First-match allow/deny rules with glob patterns:

```json
{
  "policies": [
    { "effect": "deny", "tools": ["*__delete_*", "*__destroy_*"] },
    { "effect": "deny", "tools": ["slack__*"], "tags": ["comms"] },
    { "effect": "allow", "tools": ["*"] }
  ]
}
```

### Health Checks

Automatic periodic health probes on upstream servers. Unhealthy servers are removed from the tool list, and clients are notified via `notifications/tools/list_changed`.

```json
{
  "healthCheck": {
    "enabled": true,
    "intervalMs": 30000,
    "timeoutMs": 5000
  }
}
```

### Audit Trail

Every tool call, denial, and error is appended to a hash-chained SQLite store. Each row carries a SHA-256 of its canonical contents linked to the previous row, so accidental corruption and tampering by attackers without DB access are detectable.

```bash
mavryn audit                       # View recent entries
mavryn audit --tail 50             # Last 50 entries
mavryn audit --decision deny       # Only denials
mavryn audit --tool github__*      # Filter by tool name
mavryn audit --user alice          # Per-user attribution
mavryn audit --json                # Raw JSONL with full row + hashes

mavryn audit verify                # Walk the chain; exit 1 on tamper
mavryn audit export --format csv   # Stream full DB for SIEM/auditor
mavryn audit backup audit-snapshot.db  # Online backup, safe while writing
```

Enable in config:

```json
{
  "audit": {
    "enabled": true,
    "file": ".mavryn/audit.db"
  }
}
```

#### Operator-tamper defense (v0.5+)

Plain SHA-256 chaining proves internal consistency but does not defend against an attacker with write access to the audit DB (including its `-wal` sidecar): they can edit a row and recompute the chain forward. To close that gap, configure `audit.macKey`. Each new row gets an HMAC-SHA256 over its canonical payload using a key that lives outside the DB. `mavryn audit verify` checks both the hash chain and the MACs — an attacker without the key cannot forge MACs, so any rewrite is detected.

```bash
# Generate a 32-byte key (one-time)
openssl rand -base64 32

# Option 1 — env var (simplest, fine for dev)
export MAVRYN_AUDIT_MAC_KEY='base64-string-from-above'
```

```json
{
  "audit": {
    "enabled": true,
    "file": ".mavryn/audit.db",
    "macKey": { "source": "env", "ref": "MAVRYN_AUDIT_MAC_KEY" }
  }
}
```

```json
// Option 2 — file (k8s secret mounts, systemd LoadCredential)
{
  "audit": {
    "enabled": true,
    "file": ".mavryn/audit.db",
    "macKey": { "source": "file", "ref": "/var/run/secrets/mavryn/audit.key" }
  }
}
```

If `audit.macKey` is configured but the source can't be loaded (env var unset, file missing, key value contains non-base64 characters, key not 32 bytes after decode), `mavryn serve` and `mavryn audit verify` exit non-zero with a specific error rather than silently writing or verifying nothing. Misconfiguration is loud — including a single typo in the key, since `Buffer.from(str, "base64")` on its own would silently produce derived garbage.

A standalone Python reference verifier is at [`verifier/mavryn_verify.py`](verifier/mavryn_verify.py). It uses only the Python stdlib (`sqlite3`, `hashlib`, `hmac`, `json`) and reproduces the TS canonical hashing and HMAC byte-for-byte. Auditors can copy a Mavryn DB off-host and verify cryptographic integrity without running any Mavryn binary. The vitest suite cross-checks the two implementations on every test run.

A small `audit_meta` table records `first_mac_seq` (the seq of the first row written under a configured key). Verify enforces a monotonicity invariant: every row at `seq >= first_mac_seq` must be MAC'd. An attacker with DB write but no key access cannot launder a tampered row by stripping its `event_mac` and recomputing the unkeyed hash chain — the missing MAC trips monotonicity. Stripping MACs from the entire column AND deleting the watermark row is the only way to evade detection, and that combined attack still exits non-zero with a warning that distinguishes it from a freshly-enabled key.

#### What HMAC alone does *not* defend against

- **An operator who has BOTH DB write access AND the same key.** They can rewrite a row, recompute its MAC, and verify still passes. v0.6's external anchoring (S3 object lock, transparency log) is the layered defense — the schema already reserves `anchor_hash`, `anchor_seq`, `anchor_source` columns so v0.6 is a feature add.
- **Truncation.** An attacker with DB write can `DELETE FROM events WHERE seq > N` and verify still reports intact. The HMAC chain proves rows that *exist* are unaltered; it cannot prove rows weren't *removed* off the end. Mitigate today by exporting periodically with `mavryn audit export` and keeping the exports off-host. v0.6 anchoring will detect truncation as well.
- **Snapshot rollback.** Restoring a yesterday's `audit.db` from a backup, then writing new rows on top of the restored state, is invisible to the in-DB chain. Same mitigations as truncation.

#### Key rotation

v0.5 has no built-in re-MAC migration. Changing `audit.macKey` makes pre-rotation MACs unverifiable under the new key, and re-MACing existing rows would forge a false attestation that those rows existed at rotation time — so it isn't offered. If you must rotate:

1. Export the pre-rotation events with `mavryn audit export` while the old key is still configured.
2. Verify them externally (the JSONL export is sufficient input for a Python/Go verifier reproducing JCS+HMAC).
3. Treat the export as sealed history.
4. Rotate the key; new rows MAC under the new key.

`mavryn audit verify` after rotation will fail at the first pre-rotation row with a specific "first MAC checked, likely wrong key or rotated" message. That is the design — verify is supposed to refuse to claim authenticity it can't actually prove.

#### Upgrading to v0.5

Schema migrations run automatically on first open and are wrapped in a single transaction (a partial failure rolls back cleanly, never leaving the DB half-migrated). Existing v0.3.x DBs gain four nullable columns and an `audit_meta` table; pre-v0.5 rows are not back-filled — they remain hash-only and verify reports them as legacy.

- **No `audit.macKey` configured (default):** behavior is unchanged from v0.3.x. New rows are hash-only. `verify` reports `chain intact (hash-only; no audit.macKey configured)`.
- **`audit.macKey` configured on a fresh DB:** all rows are MAC'd. `verify` reports `chain intact, N MAC-verified`.
- **`audit.macKey` configured on an existing v0.3.x DB:** old rows stay hash-only, new rows are MAC'd. `verify` reports the boundary explicitly: `chain intact (M MAC-verified, K legacy hash-only)`.
- **`audit.macKey` configured but no tool calls have happened yet:** `verify` exits non-zero with a warning. The state is indistinguishable from a tampering attempt that stripped MACs and the watermark; resolve by writing one row (any tool call) and re-running verify.

**Downgrading.** A v0.5 DB will open in v0.3.x or v0.4 — those builds don't check `user_version` and the new columns are nullable, so they happily INSERT rows with NULL `event_mac` next to your MAC'd rows. Verify on the older build wouldn't see the MACs at all. **Don't downgrade a MAC-protected DB**; if you may need to roll back, take a backup first with `mavryn audit backup audit-pre-v05.db` and downgrade onto a fresh DB.

### Evaluation Harness

Benchmark your routing quality:

```bash
mavryn eval benchmarks/my-tests.json -k 5
```

Benchmark format:

```json
[
  {
    "prompt": "read the contents of a file",
    "expectedTools": ["filesystem__read_file", "filesystem__read_text_file"]
  }
]
```

### Structured Logging

All gateway activity is logged as structured JSON to stderr. Configure the level and optional log file:

```json
{
  "log": {
    "level": "info",
    "file": ".mavryn/gateway.log"
  }
}
```

## Full Config Reference

```json
{
  "version": 1,
  "servers": [
    {
      "name": "my-server",
      "transport": {
        "type": "stdio",
        "command": "npx",
        "args": ["-y", "@some/mcp-server"],
        "env": { "API_KEY": "..." }
      },
      "enabled": true,
      "tags": ["dev", "backend"],
      "description": "My MCP server"
    }
  ],
  "filters": {
    "includeTags": [],
    "excludeTags": [],
    "includeTools": [],
    "excludeTools": []
  },
  "policies": [],
  "healthCheck": {
    "enabled": true,
    "intervalMs": 30000,
    "timeoutMs": 5000,
    "unhealthyThreshold": 3
  },
  "defaults": {
    "toolCallTimeoutMs": 30000
  },
  "audit": {
    "enabled": false,
    "file": ".mavryn/audit.db",
    "failClosed": false,
    "agentId": "my-agent",
    "macKey": { "source": "env", "ref": "MAVRYN_AUDIT_MAC_KEY" }
  },
  "log": {
    "level": "info",
    "file": null
  }
}
```

### Transport Types

- **stdio**: `{ "type": "stdio", "command": "...", "args": [...], "env": {...} }`
- **SSE**: `{ "type": "sse", "url": "https://...", "headers": {...} }`
- **Streamable HTTP**: `{ "type": "streamable-http", "url": "https://...", "headers": {...} }`

## CLI Commands

| Command | Description |
|---------|-------------|
| `mavryn init` | Create `mavryn.config.json` |
| `mavryn add <name>` | Register an upstream server |
| `mavryn remove <name>` | Remove a server |
| `mavryn list` | List registered servers |
| `mavryn serve` | Start the gateway |
| `mavryn audit` | View audit trail |
| `mavryn audit verify` | Walk the hash chain (and MACs, if `audit.macKey` is set) |
| `mavryn audit export` | Stream full audit trail as JSONL or CSV |
| `mavryn audit backup <dest>` | Online backup of the audit DB |
| `mavryn eval <file>` | Run routing benchmarks |

## Architecture

```
┌─────────────────────────────────┐
│         AI Tool / Agent         │
│   (Claude Code, Cursor, etc.)   │
└────────────┬────────────────────┘
             │ MCP (stdio)
             ▼
┌─────────────────────────────────┐
│            Mavryn               │
│  ┌───────┐ ┌──────┐ ┌───────┐   │
│  │Router │ │Policy│ │ Audit │   │
│  └───┬───┘ └──┬───┘ └───┬───┘   │
│      └────────┼──────────┘      │
│           ┌───┴───┐             │
│           │ Proxy │             │
│           └───┬───┘             │
└───────────────┼─────────────────┘
       ┌────────┼────────┐
       ▼        ▼        ▼
   ┌──────┐ ┌──────┐ ┌──────┐
   │GitHub│ │FS    │ │Slack │
   │Server│ │Server│ │Server│
   └──────┘ └──────┘ └──────┘
```

## Security

Mavryn sits between your AI tools and your MCP servers. Security is not optional.

### Secret redaction

All logs, audit entries, and error messages are scrubbed before being written. Mavryn detects and redacts:

- API keys and tokens (GitHub PATs, AWS keys, Bearer tokens, JWTs)
- Passwords and secrets in key-value pairs
- Private keys (RSA, EC, DSA, OpenSSH)
- Connection strings with embedded credentials
- Known secret field names (`password`, `token`, `api_key`, `authorization`, etc.)

Upstream responses are also scanned — if an MCP server leaks a secret in its output, Mavryn redacts it before passing it to the client.

### Environment variable references

Never put secrets in `mavryn.config.json`. Use env var references instead:

```json
{
  "env": {
    "GITHUB_PERSONAL_ACCESS_TOKEN": "$GITHUB_PERSONAL_ACCESS_TOKEN"
  }
}
```

Mavryn resolves `$VAR` and `${VAR}` syntax at runtime from the process environment. The secret never touches disk.

### Upstream response limits

Upstream responses are capped at 10MB per tool call. If a server returns a payload exceeding this limit, the response is truncated with a warning. This prevents memory exhaustion from malicious or misconfigured upstreams.

### Upstream tool name validation

Tool names from upstream servers are validated against a safe character set (`a-zA-Z0-9_-.:`). Names containing the namespace separator (`__`) are rejected to prevent namespace injection attacks. Tool counts per server are capped (default 500, configurable via `maxTools`).

### Tool call timeouts

Every upstream tool call has a timeout (default 30s, configurable per-server and globally). A hung or malicious upstream cannot block the gateway indefinitely.

### Threat model

Mavryn treats upstream MCP servers as **untrusted**. Specifically:

- **Tool names** are validated and sanitized before exposure
- **Tool responses** are shape-validated, size-limited, and secret-redacted
- **Error messages** from upstreams are redacted before reaching the client
- **Transport credentials** are resolved from environment variables, not stored in config
- **Policy enforcement** happens before execution, not after

Mavryn does **not** currently protect against:

- A compromised upstream that returns subtly wrong (but valid) data
- Side-channel attacks through timing or tool selection patterns
- Exfiltration through tool input arguments if the LLM is manipulated (prompt injection)

## License

MIT
