import { Command } from "commander";
import { existsSync } from "fs";
import { createDefaultConfig, saveConfig, resolveConfigPath } from "../../config.js";

export const initCommand = new Command("init")
  .description("Initialize a new mavryn.config.json in the current directory")
  .option("-f, --force", "Overwrite existing config")
  .action(async (opts) => {
    const configPath = resolveConfigPath();

    if (existsSync(configPath) && !opts.force) {
      console.error(`Config already exists: ${configPath}`);
      console.error("Use --force to overwrite.");
      process.exit(1);
    }

    const config = createDefaultConfig();
    const path = await saveConfig(config);
    console.log(`Created ${path}`);
    console.log("\nNext steps:");
    console.log("  mavryn add <name> --stdio <command>   Add an MCP server");
    console.log("  mavryn serve                          Start the gateway");
    console.log("\nOptional — operator-tamper defense for the audit chain (v0.5+):");
    console.log("  1. Generate a key:  openssl rand -base64 32");
    console.log("  2. Export it:       export MAVRYN_AUDIT_MAC_KEY='<base64>'");
    console.log("  3. Add to config:   audit.macKey = { source: \"env\", ref: \"MAVRYN_AUDIT_MAC_KEY\" }");
    console.log("  See README → \"Operator-tamper defense\" for the full rationale.");
  });
