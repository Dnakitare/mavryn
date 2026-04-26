import { z, ZodError } from "zod";
import { readFile, writeFile } from "fs/promises";
import { existsSync } from "fs";
import path from "path";

const StdioTransportSchema = z.object({
  type: z.literal("stdio"),
  command: z.string().min(1, "Command must not be empty"),
  args: z.array(z.string()).default([]),
  env: z.record(z.string()).optional(),
});

const SseTransportSchema = z.object({
  type: z.literal("sse"),
  url: z.string().url(),
  headers: z.record(z.string()).optional(),
});

const StreamableHttpTransportSchema = z.object({
  type: z.literal("streamable-http"),
  url: z.string().url(),
  headers: z.record(z.string()).optional(),
});

const TransportSchema = z.discriminatedUnion("type", [
  StdioTransportSchema,
  SseTransportSchema,
  StreamableHttpTransportSchema,
]);

const UpstreamServerSchema = z.object({
  name: z.string().regex(/^[a-z0-9_-]+$/, "Name must be lowercase alphanumeric with hyphens/underscores"),
  transport: TransportSchema,
  enabled: z.boolean().default(true),
  tags: z.array(z.string().min(1, "Tags must not be empty strings")).default([]),
  description: z.string().optional(),
  timeoutMs: z.number().min(1000).optional().describe("Per-server tool call timeout in milliseconds"),
  maxTools: z.number().min(1).optional().describe("Maximum number of tools to accept from this server"),
});

const PolicyRuleSchema = z.object({
  name: z.string().optional().describe("Human-readable rule name; recorded on every audit row this rule was evaluated against"),
  effect: z.enum(["allow", "deny"]),
  tools: z.array(z.string()).describe("Glob patterns matching namespaced tool names, e.g. 'github__*' or '*__delete_*'"),
  tags: z.array(z.string()).optional().describe("Only apply to servers with these tags"),
  servers: z.array(z.string()).optional().describe("Only apply to these server names"),
});

const FilterSchema = z.object({
  includeTags: z.array(z.string()).optional().describe("Only expose tools from servers with these tags"),
  excludeTags: z.array(z.string()).optional().describe("Hide tools from servers with these tags"),
  includeTools: z.array(z.string()).optional().describe("Glob patterns for tools to include"),
  excludeTools: z.array(z.string()).optional().describe("Glob patterns for tools to exclude"),
});

const HealthCheckSchema = z.object({
  enabled: z.boolean().default(true),
  intervalMs: z.number().min(5000).default(30000).describe("Health check interval in milliseconds"),
  timeoutMs: z.number().min(1000).default(5000).describe("Health check timeout in milliseconds"),
  unhealthyThreshold: z.number().min(1).default(3).describe("Consecutive failures before marking unhealthy"),
}).refine(
  (data) => data.timeoutMs < data.intervalMs,
  { message: "healthCheck.timeoutMs must be less than healthCheck.intervalMs" },
);

const MavrynConfigSchema = z.object({
  version: z.literal(1),
  servers: z.array(UpstreamServerSchema).default([]),
  filters: FilterSchema.default({}),
  policies: z.array(PolicyRuleSchema).default([]),
  healthCheck: HealthCheckSchema.default({}),
  audit: z.object({
    enabled: z.boolean().default(false),
    file: z.string().default(".mavryn/audit.db"),
    failClosed: z.boolean().default(false).describe("If true, deny tool calls when the audit log can't be written (compliance mode). If false (default), continue serving with audit silently disabled — surface in logs only."),
    agentId: z.string().optional().describe("Identifier recorded as agent_id on every audit row. Convention: a stable string that names this agent or its role (e.g. 'claude-code', 'security_reviewer', 'support-bot-v2'). Use sourceTag for fleet/deployment grouping; use agentId for the agent's identity itself."),
    macKey: z.object({
      source: z.enum(["env", "file"]).describe("Where to read the HMAC key. 'env' = read base64 key from named env var; 'file' = read base64 key from file path."),
      ref: z.string().min(1).describe("Env var name (for source=env) or file path (for source=file). The referenced value must be base64-encoded and decode to a 32-byte key."),
    }).optional().describe("Optional. When set, every new audit row gets an HMAC-SHA256 over its canonical payload, defending against operators with DB write access. Old rows (pre-v0.5 or pre-config) keep NULL event_mac. `mavryn audit verify` reads this same config to check MACs. KMS/Vault/HSM sources are reserved for v0.6+."),
  }).default({}),
  log: z.object({
    level: z.enum(["debug", "info", "warn", "error"]).default("info"),
    file: z.string().optional(),
  }).default({}),
  defaults: z.object({
    toolCallTimeoutMs: z.number().min(1000).default(30000).describe("Default timeout for upstream tool calls"),
  }).default({}),
});

export type UpstreamServerConfig = z.infer<typeof UpstreamServerSchema>;
export type MavrynConfig = z.infer<typeof MavrynConfigSchema>;
export type TransportConfig = z.infer<typeof TransportSchema>;
export type PolicyRule = z.infer<typeof PolicyRuleSchema>;
export type FilterConfig = z.infer<typeof FilterSchema>;

const CONFIG_FILENAME = "mavryn.config.json";

export function resolveConfigPath(dir?: string): string {
  return path.resolve(dir ?? process.cwd(), CONFIG_FILENAME);
}

export function resolveRelativeTo(configDir: string, filePath: string): string {
  if (path.isAbsolute(filePath)) return filePath;
  return path.resolve(configDir, filePath);
}

export async function loadConfig(dir?: string): Promise<MavrynConfig> {
  const configPath = resolveConfigPath(dir);
  if (!existsSync(configPath)) {
    throw new Error(`Config not found: ${configPath}\nRun 'mavryn init' to create one.`);
  }

  let raw: unknown;
  try {
    raw = JSON.parse(await readFile(configPath, "utf-8"));
  } catch (err) {
    throw new Error(
      `Failed to parse ${configPath}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  try {
    return MavrynConfigSchema.parse(raw);
  } catch (err) {
    if (err instanceof ZodError) {
      const issues = err.issues.map(
        (i) => `  - ${i.path.join(".")}: ${i.message}`,
      ).join("\n");
      throw new Error(`Invalid config in ${configPath}:\n${issues}`);
    }
    throw err;
  }
}

export async function saveConfig(config: MavrynConfig, dir?: string): Promise<string> {
  const configPath = resolveConfigPath(dir);
  await writeFile(configPath, JSON.stringify(config, null, 2) + "\n", "utf-8");
  return configPath;
}

export function createDefaultConfig(): MavrynConfig {
  return MavrynConfigSchema.parse({ version: 1 });
}

export { MavrynConfigSchema, UpstreamServerSchema, PolicyRuleSchema, FilterSchema };
