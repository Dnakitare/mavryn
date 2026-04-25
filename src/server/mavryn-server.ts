import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type CallToolResult,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";
import type { MavrynConfig, UpstreamServerConfig } from "../config.js";
import { UpstreamConnection, type NamespacedTool } from "../proxy/upstream.js";
import { passesFilters, evaluatePolicy } from "../proxy/policy.js";
import { HealthChecker } from "../proxy/health.js";
import { ToolRouter } from "./router.js";
import { Logger } from "../logging/logger.js";
import { AuditLog } from "../logging/audit.js";
import { redactString, enforceContentLimit } from "../security/redact.js";

export class MavrynServer {
  private config: MavrynConfig;
  private server: Server;
  private upstreams: Map<string, UpstreamConnection> = new Map();
  private serverConfigs: Map<string, UpstreamServerConfig> = new Map();
  private toolIndex: Map<string, NamespacedTool> = new Map();
  private logger: Logger;
  private audit: AuditLog;
  private router: ToolRouter;
  private healthChecker: HealthChecker | null = null;
  private rebuilding = false;

  constructor(config: MavrynConfig) {
    this.config = config;
    this.logger = new Logger(config.log.level, config.log.file);
    this.audit = new AuditLog(config.audit.enabled, config.audit.file, this.logger);
    this.router = new ToolRouter();
    this.server = new Server(
      { name: "mavryn", version: "0.1.0" },
      { capabilities: { tools: {} } },
    );

    this.setupHandlers();
  }

  async start(): Promise<void> {
    await this.connectUpstreams();
    this.buildToolIndex();

    if (this.config.healthCheck.enabled && this.upstreams.size > 0) {
      this.healthChecker = new HealthChecker(
        this.upstreams,
        this.logger,
        {
          intervalMs: this.config.healthCheck.intervalMs,
          timeoutMs: this.config.healthCheck.timeoutMs,
          unhealthyThreshold: this.config.healthCheck.unhealthyThreshold,
        },
      );
      this.healthChecker.setOnHealthChange((_name, _status) => {
        // Debounce rebuilds — health changes from concurrent checks
        // should only trigger one rebuild
        if (!this.rebuilding) {
          this.rebuilding = true;
          queueMicrotask(() => {
            this.buildToolIndex();
            this.server.notification({ method: "notifications/tools/list_changed" });
            this.rebuilding = false;
          });
        }
      });
      this.healthChecker.start();
    }

    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    this.logger.info("mavryn_started", {
      upstreams: this.upstreams.size,
      tools: this.toolIndex.size,
      healthChecks: this.config.healthCheck.enabled,
      audit: this.config.audit.enabled,
      policies: this.config.policies.length,
    });
  }

  private setupHandlers(): void {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      const tools: Tool[] = [];

      for (const nsTool of this.toolIndex.values()) {
        tools.push({
          name: nsTool.namespacedName,
          description: `[${nsTool.upstream}] ${nsTool.tool.description ?? nsTool.originalName}`,
          inputSchema: nsTool.tool.inputSchema,
          // Pass through optional metadata from upstream
          ...(nsTool.tool.annotations && { annotations: nsTool.tool.annotations }),
          ...(nsTool.tool.outputSchema && { outputSchema: nsTool.tool.outputSchema }),
        });
      }

      // Meta-tools
      tools.push({
        name: "mavryn_search",
        description: "Search available tools across all connected MCP servers. Returns ranked results with relevance scores.",
        inputSchema: {
          type: "object" as const,
          properties: {
            query: { type: "string", description: "Search query to match against tool names and descriptions" },
            server: { type: "string", description: "Filter by server name" },
            tag: { type: "string", description: "Filter by server tag" },
            limit: { type: "number", description: "Max results (default 20)" },
          },
          required: ["query"],
        },
      });

      tools.push({
        name: "mavryn_status",
        description: "Show Mavryn gateway status: connected servers, tool counts, and health.",
        inputSchema: {
          type: "object" as const,
          properties: {},
        },
      });

      return { tools };
    });

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      if (name === "mavryn_search") {
        return this.handleSearch(args as { query: string; server?: string; tag?: string; limit?: number });
      }
      if (name === "mavryn_status") {
        return this.handleStatus();
      }

      const nsTool = this.toolIndex.get(name);
      if (!nsTool) {
        return {
          content: [{ type: "text" as const, text: `Unknown tool: ${name}` }],
          isError: true,
        };
      }

      // Policy check — deny by default if server config is missing
      const serverConfig = this.serverConfigs.get(nsTool.upstream);
      if (!serverConfig) {
        return {
          content: [{ type: "text" as const, text: `Error: no config for upstream '${nsTool.upstream}'` }],
          isError: true,
        };
      }

      if (this.config.policies.length > 0) {
        const policy = evaluatePolicy(
          nsTool.namespacedName,
          nsTool.upstream,
          serverConfig,
          this.config.policies,
        );
        if (!policy.allowed) {
          this.logger.warn("tool_denied", {
            tool: nsTool.namespacedName,
            reason: policy.reason,
          });
          this.audit.toolDenied({
            upstream: nsTool.upstream,
            tool: nsTool.originalName,
            namespacedTool: nsTool.namespacedName,
            args: args ?? {},
            reason: policy.reason ?? "denied by policy",
          });
          return {
            content: [{ type: "text" as const, text: `Denied: ${policy.reason}` }],
            isError: true,
          };
        }
      }

      return this.proxyToolCall(nsTool, args ?? {});
    });
  }

  private async connectUpstreams(): Promise<void> {
    const enabledServers = this.config.servers.filter((s) => s.enabled);
    this.logger.info("connecting_upstreams", { count: enabledServers.length });

    for (const sc of this.config.servers) {
      this.serverConfigs.set(sc.name, sc);
    }

    const results = await Promise.allSettled(
      enabledServers.map(async (serverConfig) => {
        const conn = new UpstreamConnection(serverConfig, this.logger);
        await conn.connect();
        this.upstreams.set(serverConfig.name, conn);
      }),
    );

    for (let i = 0; i < results.length; i++) {
      const result = results[i];
      if (result.status === "rejected") {
        this.logger.error("upstream_skipped", {
          server: enabledServers[i].name,
          error: result.reason instanceof Error ? result.reason.message : String(result.reason),
        });
      }
    }
  }

  private buildToolIndex(): void {
    this.toolIndex.clear();
    const allTools: NamespacedTool[] = [];
    const collisions = new Set<string>();

    for (const conn of this.upstreams.values()) {
      const serverConfig = this.serverConfigs.get(conn.config.name);
      if (!serverConfig) continue;

      if (this.healthChecker) {
        const health = this.healthChecker.getStatus(conn.config.name);
        if (health?.status === "unhealthy") continue;
      }

      for (const nsTool of conn.getNamespacedTools()) {
        if (!passesFilters(nsTool, serverConfig, this.config.filters)) {
          continue;
        }

        // Detect tool name collisions
        if (this.toolIndex.has(nsTool.namespacedName)) {
          collisions.add(nsTool.namespacedName);
          this.logger.warn("tool_name_collision", {
            tool: nsTool.namespacedName,
            server: nsTool.upstream,
          });
          continue;
        }

        this.toolIndex.set(nsTool.namespacedName, nsTool);
        allTools.push(nsTool);
      }
    }

    this.router.setTools(allTools, this.serverConfigs);

    this.logger.info("tool_index_built", {
      total: this.toolIndex.size,
      collisions: collisions.size,
      byServer: Object.fromEntries(
        [...this.upstreams.entries()].map(([name, conn]) => [
          name,
          conn.getNamespacedTools().filter((t) => this.toolIndex.has(t.namespacedName)).length,
        ]),
      ),
    });
  }

  private handleSearch(args: { query: string; server?: string; tag?: string; limit?: number }): CallToolResult {
    const results = this.router.search(args.query, {
      server: args.server,
      tag: args.tag,
      limit: args.limit,
    });

    if (results.length === 0) {
      return { content: [{ type: "text", text: "No matching tools found." }] };
    }

    const lines = results.map((r, i) => {
      const desc = r.tool.tool.description ?? "(no description)";
      const scoreStr = r.score.toFixed(1);
      const signals = r.signals.join(", ");
      return `${i + 1}. **${r.tool.namespacedName}** (score: ${scoreStr})\n   ${desc}\n   Server: ${r.tool.upstream} | Signals: ${signals}`;
    });

    return {
      content: [{ type: "text", text: lines.join("\n\n") }],
    };
  }

  private handleStatus(): CallToolResult {
    const servers = [...this.upstreams.entries()].map(([name, conn]) => {
      const health = this.healthChecker?.getStatus(name);
      const toolCount = conn.getNamespacedTools().filter((t) => this.toolIndex.has(t.namespacedName)).length;
      return {
        name,
        connected: conn.isConnected(),
        health: health?.status ?? "unknown",
        tools: toolCount,
        latencyMs: health?.latencyMs ?? null,
      };
    });

    const text = [
      `**Mavryn Gateway Status**`,
      `Upstreams: ${servers.length} | Tools: ${this.toolIndex.size} | Policies: ${this.config.policies.length}`,
      ``,
      ...servers.map((s) =>
        `- **${s.name}**: ${s.health} | ${s.tools} tools | ${s.connected ? "connected" : "disconnected"}${s.latencyMs !== null ? ` | ${s.latencyMs}ms` : ""}`,
      ),
    ].join("\n");

    return { content: [{ type: "text", text }] };
  }

  private async proxyToolCall(
    nsTool: NamespacedTool,
    args: Record<string, unknown>,
  ): Promise<CallToolResult> {
    const upstream = this.upstreams.get(nsTool.upstream);
    if (!upstream || !upstream.isConnected()) {
      return {
        content: [{ type: "text", text: `Error: upstream server '${nsTool.upstream}' is not connected` }],
        isError: true,
      };
    }

    const timeoutMs = this.serverConfigs.get(nsTool.upstream)?.timeoutMs
      ?? this.config.defaults.toolCallTimeoutMs;

    const start = Date.now();
    try {
      const result = await upstream.callTool(nsTool.originalName, args, timeoutMs);

      const latencyMs = Date.now() - start;
      this.logger.toolCall(nsTool.upstream, nsTool.namespacedName, {
        success: true,
        latencyMs,
      });
      this.audit.toolCall({
        upstream: nsTool.upstream,
        tool: nsTool.originalName,
        namespacedTool: nsTool.namespacedName,
        args,
        success: true,
        latencyMs,
      });

      // Validate upstream response shape before passing through
      return this.validateToolResult(result);
    } catch (err) {
      const rawMessage = err instanceof Error ? err.message : String(err);
      const message = redactString(rawMessage);
      const latencyMs = Date.now() - start;

      this.logger.toolCall(nsTool.upstream, nsTool.namespacedName, {
        success: false,
        latencyMs,
        error: message,
      });
      this.audit.toolCall({
        upstream: nsTool.upstream,
        tool: nsTool.originalName,
        namespacedTool: nsTool.namespacedName,
        args,
        success: false,
        latencyMs,
        error: message,
      });

      return {
        content: [{ type: "text", text: `Error calling ${nsTool.originalName}: ${message}` }],
        isError: true,
      };
    }
  }

  /**
   * Validate that an upstream response conforms to CallToolResult shape.
   * If it doesn't, wrap it safely rather than passing garbage through.
   */
  private validateToolResult(result: unknown): CallToolResult {
    if (result === null || result === undefined || typeof result !== "object") {
      return {
        content: [{ type: "text", text: String(result ?? "") }],
      };
    }

    const obj = result as Record<string, unknown>;

    // Must have a content array
    if (!Array.isArray(obj.content)) {
      return {
        content: [{ type: "text", text: JSON.stringify(result) }],
      };
    }

    // Validate each content item has a type
    const validContent = obj.content.filter(
      (item: unknown) =>
        item !== null &&
        typeof item === "object" &&
        typeof (item as Record<string, unknown>).type === "string",
    );

    // Enforce content size limits
    const limitedContent = enforceContentLimit(
      validContent.length > 0 ? validContent : [{ type: "text", text: "(empty response)" }],
    );

    // Redact any secrets that may have leaked through upstream responses
    const sanitizedContent = limitedContent.map((item) => {
      const obj = item as Record<string, unknown>;
      if (obj.type === "text" && typeof obj.text === "string") {
        return { ...obj, text: redactString(obj.text) };
      }
      return item;
    });

    return {
      content: sanitizedContent as CallToolResult["content"],
      ...(typeof obj.isError === "boolean" && { isError: obj.isError }),
    };
  }

  async stop(): Promise<void> {
    this.healthChecker?.stop();
    for (const conn of this.upstreams.values()) {
      await conn.disconnect().catch(() => {});
    }
    await this.server.close();
    this.audit.close();
    this.logger.info("mavryn_stopped");
  }
}
