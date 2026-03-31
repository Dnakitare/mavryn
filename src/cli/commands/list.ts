import { Command } from "commander";
import { loadConfig } from "../../config.js";

export const listCommand = new Command("list")
  .description("List registered upstream MCP servers")
  .option("--json", "Output as JSON")
  .action(async (opts) => {
    const config = await loadConfig();

    if (config.servers.length === 0) {
      console.log("No servers registered. Run 'mavryn add' to add one.");
      return;
    }

    if (opts.json) {
      console.log(JSON.stringify(config.servers, null, 2));
      return;
    }

    console.log(`\n  Registered servers (${config.servers.length}):\n`);
    for (const server of config.servers) {
      const status = server.enabled ? "enabled" : "disabled";
      const transport = server.transport.type === "stdio"
        ? `stdio: ${server.transport.command}`
        : `${server.transport.type}: ${server.transport.url}`;
      const tags = server.tags.length > 0 ? ` [${server.tags.join(", ")}]` : "";

      console.log(`  ${server.name} (${status})`);
      console.log(`    ${transport}${tags}`);
      if (server.description) {
        console.log(`    ${server.description}`);
      }
      console.log();
    }
  });
