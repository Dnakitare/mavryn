import { Command } from "commander";
import { loadConfig, saveConfig } from "../../config.js";

export const removeCommand = new Command("remove")
  .description("Remove a registered upstream MCP server")
  .argument("<name>", "Name of the server to remove")
  .action(async (name: string) => {
    const config = await loadConfig();
    const idx = config.servers.findIndex((s) => s.name === name);

    if (idx === -1) {
      console.error(`Error: server '${name}' not found.`);
      process.exit(1);
    }

    config.servers.splice(idx, 1);
    await saveConfig(config);
    console.log(`Removed server '${name}'`);
  });
