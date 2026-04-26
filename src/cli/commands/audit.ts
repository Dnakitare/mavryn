import { Command } from "commander";
import { existsSync, createWriteStream, statSync } from "fs";
import path from "path";
import Database from "better-sqlite3";
import { loadConfig, resolveRelativeTo, resolveConfigPath } from "../../config.js";
import { SqliteAuditStore } from "../../audit/store/index.js";
import { computeEventHash } from "../../audit/hash.js";
import type { AuditEvent } from "../../audit/types.js";
import type { EventQuery } from "../../audit/store/store.js";

async function resolveAuditDbPath(): Promise<string | null> {
  const config = await loadConfig();
  if (!config.audit.enabled) {
    console.error("Audit logging is not enabled. Set audit.enabled: true in mavryn.config.json");
    process.exit(1);
  }
  const configDir = path.dirname(resolveConfigPath());
  const dbPath = resolveRelativeTo(configDir, config.audit.file);
  if (!existsSync(dbPath)) return null;
  return dbPath;
}

export const auditCommand = new Command("audit")
  .description("View the audit trail of tool calls")
  .option("--tail <n>", "Show last N entries", "20")
  .option("--json", "Output raw JSON lines (full row, including hashes)")
  .option("--tool <name>", "Filter by tool name")
  .option("--server <name>", "Filter by upstream server name")
  .option("--user <id>", "Filter by user_id")
  .option("--source <tag>", "Filter by source_tag")
  .option("--turn <id>", "Filter by turn_id (group tool calls in one LLM turn)")
  .option("--session <id>", "Filter by session id")
  .option("--decision <type>", "Filter by policy decision (allow, deny, escalate)")
  .option("--status <type>", "Filter by result status (success, error, blocked)")
  .option("--since <iso>", "Show events at or after this ISO timestamp")
  .action(async (opts) => {
    const dbPath = await resolveAuditDbPath();
    if (!dbPath) {
      console.log("No audit entries yet.");
      return;
    }

    const tail = parseInt(opts.tail, 10);
    if (isNaN(tail) || tail <= 0) {
      console.error(`Error: --tail must be a positive integer, got '${opts.tail}'`);
      process.exit(1);
    }

    const filter: EventQuery = {
      toolName: opts.tool,
      serverName: opts.server,
      userId: opts.user,
      sourceTag: opts.source,
      turnId: opts.turn,
      sessionId: opts.session,
      policyDecision: opts.decision,
      resultStatus: opts.status,
      fromTimestamp: opts.since,
      limit: tail,
    };

    const store = new SqliteAuditStore(dbPath);
    let events: AuditEvent[];
    try {
      // store.query returns DESC (most recent first) — reverse so output reads chronologically
      events = store.query(filter).reverse();
    } finally {
      store.close();
    }

    if (opts.json) {
      for (const event of events) {
        console.log(JSON.stringify(event));
      }
      return;
    }

    if (events.length === 0) {
      console.log("No matching audit entries.");
      return;
    }

    console.log(`\n  Audit trail (last ${events.length} entries):\n`);
    for (const event of events) {
      const time = event.timestamp.slice(11, 19);
      const decision = event.policyDecision;
      const status = event.resultStatus ?? "—";
      const verdict = `${decision}/${status}`.padEnd(16);
      const namespaced = `${event.serverName}__${event.toolName}`;

      const extras: string[] = [];
      if (event.userId) extras.push(`user=${event.userId}`);
      if (event.sourceTag) extras.push(`source=${event.sourceTag}`);
      if (typeof event.resultLatencyMs === "number") extras.push(`${event.resultLatencyMs}ms`);
      if (event.policyReason) extras.push(event.policyReason);
      if (event.resultSummary) extras.push(event.resultSummary);

      const extra = extras.length > 0 ? ` (${extras.join(" | ")})` : "";
      console.log(`  [${time}] ${verdict} ${namespaced}${extra}`);
    }
    console.log();
  });

// CSV cells: escape per RFC 4180 — wrap in quotes if value contains comma,
// quote, CR, or LF; double-up internal quotes. Objects/arrays serialize as
// JSON string before being escaped.
function csvCell(value: unknown): string {
  if (value === null || value === undefined) return "";
  const str = typeof value === "object" ? JSON.stringify(value) : String(value);
  if (/[",\r\n]/.test(str)) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

const CSV_COLUMNS = [
  "seq",
  "id",
  "timestamp",
  "session_id",
  "server_name",
  "agent_id",
  "tool_name",
  "tool_arguments",
  "tool_annotations",
  "policy_decision",
  "policy_reason",
  "policies_evaluated",
  "result_status",
  "result_summary",
  "result_latency_ms",
  "user_id",
  "source_tag",
  "prompt_context",
  "turn_id",
  "assistant_message",
  "system_prompt_hash",
  "meta",
  "prev_hash",
  "event_hash",
] as const;

function eventToCsvRow(ev: AuditEvent): string {
  return [
    ev.seq,
    ev.id,
    ev.timestamp,
    ev.sessionId,
    ev.serverName,
    ev.agentId,
    ev.toolName,
    ev.toolArguments,
    ev.toolAnnotations,
    ev.policyDecision,
    ev.policyReason,
    ev.policiesEvaluated,
    ev.resultStatus,
    ev.resultSummary,
    ev.resultLatencyMs,
    ev.userId,
    ev.sourceTag,
    ev.promptContext,
    ev.turnId,
    ev.assistantMessage,
    ev.systemPromptHash,
    ev.meta,
    ev.prevHash,
    ev.eventHash,
  ]
    .map(csvCell)
    .join(",");
}

auditCommand
  .command("export")
  .description("Stream the full audit trail to stdout (or --output) for SIEM/auditor handoff.")
  .option("--format <fmt>", "Output format: jsonl (default) or csv", "jsonl")
  .option("--output <path>", "Write to file instead of stdout")
  .action(async (opts) => {
    const dbPath = await resolveAuditDbPath();
    if (!dbPath) {
      console.error("No audit entries to export.");
      return;
    }

    const format = String(opts.format).toLowerCase();
    if (format !== "jsonl" && format !== "csv") {
      console.error(`Error: --format must be 'jsonl' or 'csv', got '${opts.format}'`);
      process.exit(1);
    }

    const out = opts.output ? createWriteStream(String(opts.output)) : process.stdout;

    const store = new SqliteAuditStore(dbPath);
    let count = 0;
    try {
      if (format === "csv") {
        out.write(CSV_COLUMNS.join(",") + "\n");
        for (const ev of store.iterateAllEvents()) {
          out.write(eventToCsvRow(ev) + "\n");
          count++;
        }
      } else {
        for (const ev of store.iterateAllEvents()) {
          out.write(JSON.stringify(ev) + "\n");
          count++;
        }
      }
    } finally {
      store.close();
      if (opts.output) {
        await new Promise<void>((resolve) => (out as any).end(() => resolve()));
        console.error(`Exported ${count} events to ${opts.output}`);
      }
    }
  });

auditCommand
  .command("backup <destination>")
  .description("Produce a portable single-file copy of the audit DB. Safe to run while Mavryn is writing.")
  .action(async (destination: string) => {
    const dbPath = await resolveAuditDbPath();
    if (!dbPath) {
      console.error("No audit DB to back up — Mavryn hasn't written any events yet.");
      process.exit(1);
    }

    const dest = path.resolve(process.cwd(), destination);
    if (existsSync(dest)) {
      console.error(`Refusing to overwrite existing file: ${dest}`);
      process.exit(1);
    }

    // SQLite's online backup API checkpoints WAL and produces a single
    // self-contained file — no need to also copy audit.db-wal / .db-shm.
    const src = new Database(dbPath, { readonly: true });
    try {
      await src.backup(dest);
    } finally {
      src.close();
    }

    const size = statSync(dest).size;
    console.log(`✓ Backed up audit DB to ${dest} (${(size / 1024).toFixed(1)} KB)`);
    console.log(`  Verify integrity: mavryn audit verify  (then reconfigure audit.file to point at the backup)`);
  });

auditCommand
  .command("verify")
  .description("Verify the audit chain has not been tampered with. Exits 0 if intact, 1 if broken.")
  .action(async () => {
    const dbPath = await resolveAuditDbPath();
    if (!dbPath) {
      console.log("No audit entries to verify.");
      return;
    }

    const store = new SqliteAuditStore(dbPath);
    let prevHash: string | null = null;
    let count = 0;

    try {
      // Stream rows lazily via iterateAllEvents — memory stays constant
      // regardless of DB size. Important once the audit grows past a few
      // hundred thousand rows.
      for (const ev of store.iterateAllEvents()) {
        const expectedHash = computeEventHash({
          id: ev.id,
          timestamp: ev.timestamp,
          sessionId: ev.sessionId,
          serverName: ev.serverName,
          agentId: ev.agentId,
          toolName: ev.toolName,
          toolArguments: ev.toolArguments,
          toolAnnotations: ev.toolAnnotations,
          policyDecision: ev.policyDecision,
          policiesEvaluated: ev.policiesEvaluated,
          resultStatus: ev.resultStatus,
          userId: ev.userId,
          sourceTag: ev.sourceTag,
          promptContext: ev.promptContext,
          turnId: ev.turnId,
          assistantMessage: ev.assistantMessage,
          systemPromptHash: ev.systemPromptHash,
          meta: ev.meta,
          prevHash,
        });

        const ref = `seq=${ev.seq ?? "?"} id=${ev.id}`;

        if (expectedHash !== ev.eventHash) {
          console.error(`✗ chain broken at ${ref} (timestamp=${ev.timestamp})`);
          console.error(`  expected hash: ${expectedHash}`);
          console.error(`  stored hash:   ${ev.eventHash}`);
          console.error(`  this row's contents have been modified or its prevHash is wrong`);
          process.exit(1);
        }

        if (ev.prevHash !== prevHash) {
          console.error(`✗ chain broken at ${ref} (timestamp=${ev.timestamp})`);
          console.error(`  expected prevHash: ${prevHash ?? "null"}`);
          console.error(`  stored prevHash:   ${ev.prevHash ?? "null"}`);
          console.error(`  a row before this one was deleted, inserted, or reordered`);
          process.exit(1);
        }

        prevHash = ev.eventHash;
        count++;
      }
    } finally {
      store.close();
    }

    if (count === 0) {
      console.log("No audit entries to verify.");
      return;
    }

    console.log(`✓ ${count} events verified — chain intact`);
  });
