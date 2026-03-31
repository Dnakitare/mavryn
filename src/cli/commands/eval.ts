import { Command } from "commander";
import { readFile } from "fs/promises";
import { existsSync } from "fs";
import { z } from "zod";
import { loadConfig } from "../../config.js";
import { UpstreamConnection, type NamespacedTool } from "../../proxy/upstream.js";
import { ToolRouter } from "../../server/router.js";
import { Logger } from "../../logging/logger.js";
import type { UpstreamServerConfig } from "../../config.js";

const EvalCaseSchema = z.array(
  z.object({
    prompt: z.string().min(1),
    expectedTools: z.array(z.string()).min(1),
    tags: z.array(z.string()).optional(),
  }),
);

type EvalCase = z.infer<typeof EvalCaseSchema>[number];

interface EvalResult {
  prompt: string;
  expected: string[];
  topK: string[];
  hit: boolean;
  rank: number | null;
}

export const evalCommand = new Command("eval")
  .description("Evaluate routing quality against a benchmark file")
  .argument("<benchmark>", "Path to benchmark JSON file")
  .option("-k <n>", "Top-K to check for hits", "5")
  .option("--threshold <pct>", "Minimum accuracy percentage to pass (default: report only)")
  .action(async (benchmarkPath: string, opts) => {
    if (!existsSync(benchmarkPath)) {
      console.error(`Benchmark file not found: ${benchmarkPath}`);
      process.exit(1);
    }

    const k = parseInt(opts.k, 10);
    if (isNaN(k) || k <= 0) {
      console.error(`Error: -k must be a positive integer, got '${opts.k}'`);
      process.exit(1);
    }

    let threshold: number | null = null;
    if (opts.threshold) {
      threshold = parseFloat(opts.threshold);
      if (isNaN(threshold) || threshold < 0 || threshold > 100) {
        console.error(`Error: --threshold must be a number between 0 and 100, got '${opts.threshold}'`);
        process.exit(1);
      }
    }

    // Parse and validate benchmark file
    let cases: EvalCase[];
    try {
      const raw = JSON.parse(await readFile(benchmarkPath, "utf-8"));
      cases = EvalCaseSchema.parse(raw);
    } catch (err) {
      console.error(`Error: invalid benchmark file: ${err instanceof Error ? err.message : String(err)}`);
      process.exit(1);
    }

    const config = await loadConfig();
    const logger = new Logger("error");

    // Connect to upstreams
    console.log("Connecting to upstream servers...");
    const upstreams = new Map<string, UpstreamConnection>();
    const serverConfigs = new Map<string, UpstreamServerConfig>();

    for (const sc of config.servers.filter((s) => s.enabled)) {
      serverConfigs.set(sc.name, sc);
      try {
        const conn = new UpstreamConnection(sc, logger);
        await conn.connect();
        upstreams.set(sc.name, conn);
      } catch {
        console.error(`  Failed to connect: ${sc.name}`);
      }
    }

    // Build tool index
    const allTools: NamespacedTool[] = [];
    for (const conn of upstreams.values()) {
      allTools.push(...conn.getNamespacedTools());
    }

    console.log(`Connected. ${allTools.length} tools indexed.\n`);

    // Set up router and run benchmarks
    const router = new ToolRouter();
    router.setTools(allTools, serverConfigs);

    const results: EvalResult[] = [];

    for (const tc of cases) {
      const ranked = router.search(tc.prompt, { limit: k });
      const topK = ranked.map((r) => r.tool.namespacedName);
      const hit = tc.expectedTools.some((e) => topK.includes(e));
      let rank: number | null = null;

      for (const expected of tc.expectedTools) {
        const idx = topK.indexOf(expected);
        if (idx !== -1 && (rank === null || idx < rank)) {
          rank = idx + 1;
        }
      }

      results.push({ prompt: tc.prompt, expected: tc.expectedTools, topK, hit, rank });
    }

    // Disconnect upstreams (always, even if benchmark fails)
    for (const conn of upstreams.values()) {
      await conn.disconnect().catch(() => {});
    }

    // Print results
    const hits = results.filter((r) => r.hit).length;
    const total = results.length;
    const accuracy = total > 0 ? (hits / total) * 100 : 0;

    console.log(`  Evaluation Results (top-${k})`);
    console.log(`  ${"─".repeat(50)}`);

    for (const r of results) {
      const icon = r.hit ? "PASS" : "FAIL";
      const rankStr = r.rank !== null ? `rank ${r.rank}` : "not found";
      console.log(`  [${icon}] "${r.prompt}"`);
      console.log(`         Expected: ${r.expected.join(", ")}`);
      console.log(`         Got: ${r.topK.slice(0, 3).join(", ") || "(none)"} (${rankStr})`);
      console.log();
    }

    console.log(`  ${"─".repeat(50)}`);
    console.log(`  Accuracy: ${hits}/${total} (${accuracy.toFixed(1)}%)\n`);

    if (threshold !== null && accuracy < threshold) {
      console.error(`  FAILED: accuracy ${accuracy.toFixed(1)}% is below threshold ${threshold}%`);
      process.exit(1);
    }
  });
