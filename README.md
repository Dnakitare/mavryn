# Mavryn

The MCP control plane — one server to route them all.

Mavryn is a single MCP server that proxies multiple upstream MCP servers. Instead of configuring 15 servers in your AI tool, you configure one: Mavryn. It handles discovery, namespacing, routing, policy enforcement, and observability.

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

Every tool call, denial, and error is logged to a JSONL file:

```bash
mavryn audit               # View recent entries
mavryn audit --tail 50     # Last 50 entries
mavryn audit --filter tool_denied  # Only denials
mavryn audit --json        # Raw JSONL output
```

Enable in config:

```json
{
  "audit": {
    "enabled": true,
    "file": ".mavryn/audit.jsonl"
  }
}
```

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
    "file": ".mavryn/audit.jsonl"
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
| `mavryn eval <file>` | Run routing benchmarks |

## Architecture

```
┌─────────────────────────────────┐
│         AI Tool / Agent         │
│   (Claude Code, Cursor, etc.)  │
└────────────┬────────────────────┘
             │ MCP (stdio)
             ▼
┌─────────────────────────────────┐
│            Mavryn               │
│  ┌───────┐ ┌──────┐ ┌───────┐  │
│  │Router │ │Policy│ │ Audit │  │
│  └───┬───┘ └──┬───┘ └───┬───┘  │
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

## License

MIT
