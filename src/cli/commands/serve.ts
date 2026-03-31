import { Command } from "commander";
import { loadConfig } from "../../config.js";
import { MavrynServer } from "../../server/mavryn-server.js";

export const serveCommand = new Command("serve")
  .description("Start the Mavryn MCP gateway server")
  .action(async () => {
    const config = await loadConfig();

    if (config.servers.length === 0) {
      console.error("No servers registered. Run 'mavryn add' to add one first.");
      process.exit(1);
    }

    const enabledCount = config.servers.filter((s) => s.enabled).length;
    if (enabledCount === 0) {
      console.error("All servers are disabled. Enable at least one server.");
      process.exit(1);
    }

    const server = new MavrynServer(config);

    let shuttingDown = false;
    const shutdown = async () => {
      if (shuttingDown) return;
      shuttingDown = true;
      try {
        await server.stop();
      } catch {
        // Best-effort shutdown
      }
      process.exit(0);
    };

    process.on("SIGINT", shutdown);
    process.on("SIGTERM", shutdown);

    await server.start();
  });
