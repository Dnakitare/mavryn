import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import type { UpstreamServerConfig, TransportConfig } from "../config.js";
import type { Logger } from "../logging/logger.js";

// Only allow safe characters in tool names from upstream servers.
// This prevents namespace injection (e.g., tool named "other__admin_delete").
const SAFE_TOOL_NAME = /^[a-zA-Z0-9_\-.:]+$/;

export interface NamespacedTool {
  namespacedName: string;
  originalName: string;
  upstream: string;
  tool: Tool;
}

export class UpstreamConnection {
  readonly config: UpstreamServerConfig;
  private client: Client;
  private transport: ReturnType<UpstreamConnection["createTransport"]> | null = null;
  private logger: Logger;
  private tools: Tool[] = [];
  private _connected = false;

  constructor(config: UpstreamServerConfig, logger: Logger) {
    this.config = config;
    this.logger = logger;
    this.client = new Client(
      { name: `mavryn-proxy/${config.name}`, version: "0.1.0" },
      { capabilities: {} },
    );

    // Listen for transport close to update connection state
    this.client.onclose = () => {
      if (this._connected) {
        this._connected = false;
        this.logger.warn("upstream_transport_closed", { server: this.config.name });
      }
    };
  }

  async connect(): Promise<void> {
    this.transport = this.createTransport(this.config.transport);
    try {
      await this.client.connect(this.transport);
      this._connected = true;
      this.logger.info("upstream_connected", { server: this.config.name });
      await this.refreshTools();
    } catch (err) {
      this._connected = false;
      this.logger.error("upstream_connect_failed", {
        server: this.config.name,
        error: err instanceof Error ? err.message : String(err),
      });
      throw err;
    }
  }

  async disconnect(): Promise<void> {
    if (this._connected) {
      this._connected = false;
      await this.client.close();
      this.logger.info("upstream_disconnected", { server: this.config.name });
    }
  }

  async refreshTools(): Promise<void> {
    const allTools: Tool[] = [];
    let cursor: string | undefined;
    const maxTools = this.config.maxTools ?? 500;

    // Handle pagination
    do {
      const result = await this.client.listTools(cursor ? { cursor } : undefined);
      allTools.push(...result.tools);
      cursor = result.nextCursor;

      if (allTools.length >= maxTools) {
        this.logger.warn("upstream_tool_limit_reached", {
          server: this.config.name,
          limit: maxTools,
          total: allTools.length,
        });
        break;
      }
    } while (cursor);

    // Validate and filter tool names
    const validTools: Tool[] = [];
    for (const tool of allTools) {
      if (!SAFE_TOOL_NAME.test(tool.name)) {
        this.logger.warn("upstream_tool_name_rejected", {
          server: this.config.name,
          tool: tool.name,
          reason: "contains unsafe characters",
        });
        continue;
      }
      // Reject tools whose names contain the namespace separator
      if (tool.name.includes("__")) {
        this.logger.warn("upstream_tool_name_rejected", {
          server: this.config.name,
          tool: tool.name,
          reason: "contains namespace separator '__'",
        });
        continue;
      }
      validTools.push(tool);
    }

    this.tools = validTools;
    this.logger.info("tools_discovered", {
      server: this.config.name,
      count: this.tools.length,
      rejected: allTools.length - validTools.length,
      tools: this.tools.map((t) => t.name),
    });
  }

  getTools(): Tool[] {
    return this.tools;
  }

  getNamespacedTools(): NamespacedTool[] {
    return this.tools.map((tool) => ({
      namespacedName: `${this.config.name}__${tool.name}`,
      originalName: tool.name,
      upstream: this.config.name,
      tool,
    }));
  }

  async callTool(
    toolName: string,
    args: Record<string, unknown>,
    timeoutMs: number,
  ): Promise<unknown> {
    if (!this._connected) {
      throw new Error(`Upstream '${this.config.name}' is not connected`);
    }

    const result = await Promise.race([
      this.client.callTool({ name: toolName, arguments: args }),
      new Promise<never>((_, reject) =>
        setTimeout(
          () => reject(new Error(`Tool call timed out after ${timeoutMs}ms`)),
          timeoutMs,
        ),
      ),
    ]);

    return result;
  }

  isConnected(): boolean {
    return this._connected;
  }

  private createTransport(config: TransportConfig) {
    switch (config.type) {
      case "stdio":
        return new StdioClientTransport({
          command: config.command,
          args: config.args,
          env: config.env as Record<string, string> | undefined,
        });
      case "sse":
        return new SSEClientTransport(new URL(config.url), {
          requestInit: config.headers
            ? { headers: config.headers }
            : undefined,
        });
      case "streamable-http":
        return new StreamableHTTPClientTransport(new URL(config.url), {
          requestInit: config.headers
            ? { headers: config.headers }
            : undefined,
        });
    }
  }
}
