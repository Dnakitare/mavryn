import { appendFileSync, writeFileSync } from "fs";

export type LogLevel = "debug" | "info" | "warn" | "error";

interface LogEntry {
  timestamp: string;
  level: LogLevel;
  event: string;
  [key: string]: unknown;
}

const LEVEL_PRIORITY: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

export class Logger {
  private level: LogLevel;
  private logFile?: string;

  constructor(level: LogLevel = "info", logFile?: string) {
    this.level = level;
    this.logFile = logFile;
  }

  private shouldLog(level: LogLevel): boolean {
    return LEVEL_PRIORITY[level] >= LEVEL_PRIORITY[this.level];
  }

  private write(entry: LogEntry): void {
    if (!this.shouldLog(entry.level)) return;

    let line: string;
    try {
      line = JSON.stringify(entry);
    } catch {
      line = JSON.stringify({
        timestamp: entry.timestamp,
        level: entry.level,
        event: entry.event,
        error: "Failed to serialize log entry",
      });
    }

    if (this.logFile) {
      try {
        appendFileSync(this.logFile, line + "\n");
      } catch {
        // Log file write failure — fall through to stderr
      }
    }

    // Always write to stderr (stdout is reserved for MCP protocol)
    process.stderr.write(line + "\n");
  }

  debug(event: string, data?: Record<string, unknown>): void {
    this.write({ timestamp: new Date().toISOString(), level: "debug", event, ...data });
  }

  info(event: string, data?: Record<string, unknown>): void {
    this.write({ timestamp: new Date().toISOString(), level: "info", event, ...data });
  }

  warn(event: string, data?: Record<string, unknown>): void {
    this.write({ timestamp: new Date().toISOString(), level: "warn", event, ...data });
  }

  error(event: string, data?: Record<string, unknown>): void {
    this.write({ timestamp: new Date().toISOString(), level: "error", event, ...data });
  }

  toolCall(
    upstream: string,
    tool: string,
    result: { success: boolean; latencyMs: number; error?: string },
  ): void {
    this.write({
      timestamp: new Date().toISOString(),
      level: "info",
      event: "tool_call",
      upstream,
      tool,
      ...result,
    });
  }
}
