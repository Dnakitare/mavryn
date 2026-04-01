import { appendFileSync, mkdirSync } from "fs";
import path from "path";
import type { Logger } from "./logger.js";
import { redactValue } from "../security/redact.js";

export interface AuditEntry {
  timestamp: string;
  event: "tool_call" | "tool_denied" | "tool_error" | "upstream_connect" | "upstream_disconnect";
  upstream?: string;
  tool?: string;
  namespacedTool?: string;
  result?: "success" | "error" | "denied";
  latencyMs?: number;
  error?: string;
  policyReason?: string;
}

export class AuditLog {
  private filePath: string;
  private enabled: boolean;
  private initialized = false;
  private logger: Logger;
  private writeable = true;

  constructor(enabled: boolean, filePath: string, logger: Logger) {
    this.enabled = enabled;
    this.filePath = filePath;
    this.logger = logger;
  }

  private ensureDir(): void {
    if (this.initialized) return;
    const dir = path.dirname(this.filePath);
    try {
      mkdirSync(dir, { recursive: true });
    } catch {
      // Directory may already exist
    }
    this.initialized = true;
  }

  write(entry: AuditEntry): void {
    if (!this.enabled || !this.writeable) return;
    this.ensureDir();

    let line: string;
    try {
      line = JSON.stringify(redactValue(entry)) + "\n";
    } catch {
      return;
    }

    try {
      appendFileSync(this.filePath, line);
    } catch (err) {
      // Log the failure once, then disable to avoid spam
      this.logger.error("audit_write_failed", {
        file: this.filePath,
        error: err instanceof Error ? err.message : String(err),
      });
      this.writeable = false;
    }
  }

  toolCall(data: {
    upstream: string;
    tool: string;
    namespacedTool: string;
    success: boolean;
    latencyMs: number;
    error?: string;
  }): void {
    this.write({
      timestamp: new Date().toISOString(),
      event: data.success ? "tool_call" : "tool_error",
      upstream: data.upstream,
      tool: data.tool,
      namespacedTool: data.namespacedTool,
      result: data.success ? "success" : "error",
      latencyMs: data.latencyMs,
      error: data.error,
    });
  }

  toolDenied(data: {
    upstream: string;
    tool: string;
    namespacedTool: string;
    reason: string;
  }): void {
    this.write({
      timestamp: new Date().toISOString(),
      event: "tool_denied",
      upstream: data.upstream,
      tool: data.tool,
      namespacedTool: data.namespacedTool,
      result: "denied",
      policyReason: data.reason,
    });
  }
}
