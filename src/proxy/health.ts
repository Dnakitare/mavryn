import type { UpstreamConnection } from "./upstream.js";
import type { Logger } from "../logging/logger.js";

export type HealthStatus = "healthy" | "unhealthy" | "unknown";

interface ServerHealth {
  status: HealthStatus;
  lastCheck: Date | null;
  lastSuccess: Date | null;
  consecutiveFailures: number;
  latencyMs: number | null;
}

export class HealthChecker {
  private upstreams: Map<string, UpstreamConnection>;
  private health: Map<string, ServerHealth> = new Map();
  private logger: Logger;
  private intervalMs: number;
  private timeoutMs: number;
  private unhealthyThreshold: number;
  private timer: ReturnType<typeof setInterval> | null = null;
  private checking = false;
  private onHealthChange?: (serverName: string, status: HealthStatus) => void;

  constructor(
    upstreams: Map<string, UpstreamConnection>,
    logger: Logger,
    opts: { intervalMs: number; timeoutMs: number; unhealthyThreshold: number },
  ) {
    this.upstreams = upstreams;
    this.logger = logger;
    this.intervalMs = opts.intervalMs;
    this.timeoutMs = opts.timeoutMs;
    this.unhealthyThreshold = opts.unhealthyThreshold;

    for (const name of upstreams.keys()) {
      this.health.set(name, {
        status: "unknown",
        lastCheck: null,
        lastSuccess: null,
        consecutiveFailures: 0,
        latencyMs: null,
      });
    }
  }

  setOnHealthChange(cb: (serverName: string, status: HealthStatus) => void): void {
    this.onHealthChange = cb;
  }

  start(): void {
    this.checkAll();
    this.timer = setInterval(() => this.checkAll(), this.intervalMs);
  }

  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  getStatus(serverName: string): ServerHealth | undefined {
    return this.health.get(serverName);
  }

  getAllStatus(): Map<string, ServerHealth> {
    return new Map(this.health);
  }

  private async checkAll(): Promise<void> {
    // Guard against re-entrance if health checks take longer than the interval
    if (this.checking) return;
    this.checking = true;

    try {
      const checks = [...this.upstreams.entries()].map(([name, conn]) =>
        this.checkOne(name, conn),
      );
      await Promise.allSettled(checks);
    } finally {
      this.checking = false;
    }
  }

  private async checkOne(name: string, conn: UpstreamConnection): Promise<void> {
    const entry = this.health.get(name)!;
    const prevStatus = entry.status;
    const start = Date.now();

    try {
      // Use a simple connectivity check — does the connection respond?
      // We use listTools as a lightweight probe but DON'T use the results
      // to mutate tool state. Tool refresh is handled separately by the server.
      const responded = await Promise.race([
        conn.isConnected()
          ? conn.callTool("__health_probe__", {}, this.timeoutMs)
              .then(() => true)
              .catch((err) => {
                // "Unknown tool" error means the server is responsive
                const msg = err instanceof Error ? err.message : String(err);
                return msg.includes("timed out") ? false : true;
              })
          : Promise.resolve(false),
        new Promise<false>((resolve) =>
          setTimeout(() => resolve(false), this.timeoutMs),
        ),
      ]);

      const latency = Date.now() - start;

      if (responded) {
        entry.lastSuccess = new Date();
        entry.consecutiveFailures = 0;
        entry.latencyMs = latency;

        if (prevStatus !== "healthy") {
          entry.status = "healthy";
        }
      } else {
        entry.consecutiveFailures++;
        entry.latencyMs = null;

        // Only mark unhealthy after threshold consecutive failures
        if (entry.consecutiveFailures >= this.unhealthyThreshold) {
          entry.status = "unhealthy";
        }
      }
    } catch {
      entry.consecutiveFailures++;
      entry.latencyMs = null;

      if (entry.consecutiveFailures >= this.unhealthyThreshold) {
        entry.status = "unhealthy";
      }
    }

    entry.lastCheck = new Date();

    if (prevStatus !== entry.status) {
      this.logger.info("health_change", {
        server: name,
        from: prevStatus,
        to: entry.status,
        consecutiveFailures: entry.consecutiveFailures,
      });
      this.onHealthChange?.(name, entry.status);
    }
  }
}
