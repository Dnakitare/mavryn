import { Command } from "commander";
import { loadConfig, saveConfig, type UpstreamServerConfig } from "../../config.js";

export const addCommand = new Command("add")
  .description("Register an upstream MCP server")
  .argument("<name>", "Unique name for this server (lowercase, alphanumeric, hyphens, underscores)")
  .option("--stdio <command>", "Stdio transport command (e.g. 'npx -y @some/mcp-server')")
  .option("--args <args...>", "Arguments for stdio command")
  .option("--sse <url>", "SSE transport URL")
  .option("--http <url>", "Streamable HTTP transport URL")
  .option("--tags <tags...>", "Tags for categorization")
  .option("--description <desc>", "Description of this server")
  .option("--env <pairs...>", "Environment variables as KEY=VALUE pairs (stdio only)")
  .option("--timeout <ms>", "Tool call timeout in milliseconds for this server")
  .option("--max-tools <n>", "Maximum number of tools to accept from this server")
  .action(async (name: string, opts) => {
    if (!/^[a-z0-9_-]+$/.test(name)) {
      console.error("Error: name must be lowercase alphanumeric with hyphens/underscores");
      process.exit(1);
    }

    // Determine transport
    const transportCount = [opts.stdio, opts.sse, opts.http].filter(Boolean).length;
    if (transportCount !== 1) {
      console.error("Error: specify exactly one transport: --stdio, --sse, or --http");
      process.exit(1);
    }

    // Validate that --args and --env are only used with --stdio
    if (!opts.stdio && opts.args) {
      console.error("Error: --args can only be used with --stdio");
      process.exit(1);
    }
    if (!opts.stdio && opts.env) {
      console.error("Error: --env can only be used with --stdio");
      process.exit(1);
    }

    // Validate URL for HTTP transports
    if (opts.sse || opts.http) {
      const url = opts.sse ?? opts.http;
      try {
        new URL(url);
      } catch {
        console.error(`Error: invalid URL: ${url}`);
        process.exit(1);
      }
    }

    let transport: UpstreamServerConfig["transport"];

    if (opts.stdio) {
      const env = parseEnvPairs(opts.env);
      transport = {
        type: "stdio" as const,
        command: opts.stdio,
        args: opts.args ?? [],
        ...(env && { env }),
      };
    } else if (opts.sse) {
      transport = { type: "sse" as const, url: opts.sse };
    } else {
      transport = { type: "streamable-http" as const, url: opts.http };
    }

    const config = await loadConfig();

    if (config.servers.some((s) => s.name === name)) {
      console.error(`Error: server '${name}' already exists. Remove it first with 'mavryn remove ${name}'.`);
      process.exit(1);
    }

    // Validate numeric options
    const timeout = opts.timeout ? parsePositiveInt(opts.timeout, "--timeout") : undefined;
    const maxTools = opts.maxTools ? parsePositiveInt(opts.maxTools, "--max-tools") : undefined;

    const server: UpstreamServerConfig = {
      name,
      transport,
      enabled: true,
      tags: opts.tags ?? [],
      description: opts.description,
      ...(timeout && { timeoutMs: timeout }),
      ...(maxTools && { maxTools }),
    };

    config.servers.push(server);
    await saveConfig(config);
    console.log(`Added server '${name}' (${transport.type})`);
  });

function parseEnvPairs(pairs?: string[]): Record<string, string> | undefined {
  if (!pairs || pairs.length === 0) return undefined;
  const env: Record<string, string> = {};
  for (const pair of pairs) {
    const eq = pair.indexOf("=");
    if (eq === -1) {
      console.error(`Error: invalid env pair '${pair}', expected KEY=VALUE`);
      process.exit(1);
    }
    env[pair.slice(0, eq)] = pair.slice(eq + 1);
  }
  return env;
}

function parsePositiveInt(value: string, flag: string): number {
  const n = parseInt(value, 10);
  if (isNaN(n) || n <= 0) {
    console.error(`Error: ${flag} must be a positive integer, got '${value}'`);
    process.exit(1);
  }
  return n;
}
