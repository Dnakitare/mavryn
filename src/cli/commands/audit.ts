import { Command } from "commander";
import { existsSync } from "fs";
import path from "path";
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
    let events: AuditEvent[];
    try {
      events = store.getAllEvents(Number.MAX_SAFE_INTEGER, 0);
    } finally {
      store.close();
    }

    if (events.length === 0) {
      console.log("No audit entries to verify.");
      return;
    }

    let prevHash: string | null = null;
    for (const ev of events) {
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
    }

    console.log(`✓ ${events.length} events verified — chain intact`);
  });
