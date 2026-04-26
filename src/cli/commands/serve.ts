import { Command } from "commander";
import path from "path";
import { loadConfig, resolveConfigPath } from "../../config.js";
import { MavrynServer } from "../../server/mavryn-server.js";
import { loadMacKeyFromConfig, MacKeyLoadError } from "../../audit/keyLoader.js";

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

    // Resolve audit.macKey before constructing the server. If it's configured
    // but unloadable (env var unset, file missing, wrong length), fail loudly
    // here — silent fallback would let MAC writes silently no-op, which is
    // worse than not starting.
    let macKey: Buffer | null = null;
    try {
      const configDir = path.dirname(resolveConfigPath());
      macKey = loadMacKeyFromConfig(config.audit, configDir);
    } catch (err) {
      if (err instanceof MacKeyLoadError) {
        console.error(`Error: ${err.message}`);
        process.exit(1);
      }
      throw err;
    }

    const server = new MavrynServer(config, macKey);

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
