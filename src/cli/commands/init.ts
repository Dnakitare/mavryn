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
  });
