import { Command } from "commander";
import { loadConfig, resolveRelativeTo, resolveConfigPath } from "../../config.js";
import { createReadStream, existsSync } from "fs";
import { createInterface } from "readline";
import path from "path";

export const auditCommand = new Command("audit")
  .description("View the audit trail of tool calls")
  .option("--tail <n>", "Show last N entries", "20")
  .option("--json", "Output raw JSON lines")
  .option("--filter <event>", "Filter by event type (tool_call, tool_denied, tool_error)")
  .action(async (opts) => {
    const config = await loadConfig();

    if (!config.audit.enabled) {
      console.error("Audit logging is not enabled. Set audit.enabled: true in mavryn.config.json");
      process.exit(1);
    }

    // Resolve audit file path relative to config directory
    const configDir = path.dirname(resolveConfigPath());
    const auditPath = resolveRelativeTo(configDir, config.audit.file);

    if (!existsSync(auditPath)) {
      console.log("No audit entries yet.");
      return;
    }

    const tail = parseInt(opts.tail, 10);
    if (isNaN(tail) || tail <= 0) {
      console.error(`Error: --tail must be a positive integer, got '${opts.tail}'`);
      process.exit(1);
    }

    // Stream the file line by line, keeping only the last N entries in a ring buffer
    const entries: Array<Record<string, unknown>> = [];
    const rl = createInterface({
      input: createReadStream(auditPath, "utf-8"),
      crlfDelay: Infinity,
    });

    for await (const line of rl) {
      if (!line.trim()) continue;

      let entry: Record<string, unknown>;
      try {
        entry = JSON.parse(line);
      } catch {
        continue; // Skip malformed lines
      }

      if (opts.filter && entry.event !== opts.filter) continue;

      entries.push(entry);
      if (entries.length > tail) {
        entries.shift();
      }
    }

    if (opts.json) {
      for (const entry of entries) {
        console.log(JSON.stringify(entry));
      }
      return;
    }

    if (entries.length === 0) {
      console.log("No matching audit entries.");
      return;
    }

    console.log(`\n  Audit trail (last ${entries.length} entries):\n`);
    for (const entry of entries) {
      const time = typeof entry.timestamp === "string" ? entry.timestamp.slice(11, 19) : "??:??:??";
      const event = String(entry.event ?? "unknown");
      const tool = String(entry.namespacedTool ?? entry.upstream ?? "");
      const result = entry.result ? String(entry.result) : "";
      const latency = typeof entry.latencyMs === "number" ? `${entry.latencyMs}ms` : "";
      const extra = [result, latency, entry.error, entry.policyReason]
        .filter((v) => v && typeof v === "string")
        .join(" | ");

      console.log(`  [${time}] ${event.padEnd(16)} ${tool}${extra ? ` (${extra})` : ""}`);
    }
    console.log();
  });
