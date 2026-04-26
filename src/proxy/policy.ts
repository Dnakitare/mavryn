import type { PolicyRule, FilterConfig, UpstreamServerConfig } from "../config.js";
import type { NamespacedTool } from "./upstream.js";

/**
 * Simple glob matching: supports * (any chars) and ? (single char).
 * Uses a bounded approach to prevent ReDoS — limits input length and
 * converts * to a non-greedy match within safe bounds.
 */
function globMatch(pattern: string, str: string): boolean {
  // Safety: reject unreasonably long strings
  if (str.length > 500 || pattern.length > 200) return false;

  let regexStr = "^";
  for (const char of pattern) {
    switch (char) {
      case "*":
        regexStr += "[^]*?";
        break;
      case "?":
        regexStr += ".";
        break;
      case ".":
      case "+":
      case "^":
      case "$":
      case "{":
      case "}":
      case "(":
      case ")":
      case "|":
      case "[":
      case "]":
      case "\\":
        regexStr += "\\" + char;
        break;
      default:
        regexStr += char;
    }
  }
  regexStr += "$";

  try {
    return new RegExp(regexStr).test(str);
  } catch {
    return false;
  }
}

function matchesAnyGlob(patterns: string[], str: string): boolean {
  return patterns.some((p) => globMatch(p, str));
}

/**
 * Apply tag/tool filters to determine if a tool should be exposed.
 *
 * Order of evaluation:
 *   1. includeTags (if set, server must have at least one matching tag)
 *   2. excludeTags (if server has any matching tag, exclude)
 *   3. includeTools (if set, tool name must match at least one pattern)
 *   4. excludeTools (if tool name matches any pattern, exclude)
 *
 * Exclude always wins over include at the same level.
 */
export function passesFilters(
  tool: NamespacedTool,
  serverConfig: UpstreamServerConfig,
  filters: FilterConfig,
): boolean {
  if (filters.includeTags && filters.includeTags.length > 0) {
    if (!filters.includeTags.some((t) => serverConfig.tags.includes(t))) {
      return false;
    }
  }
  if (filters.excludeTags && filters.excludeTags.length > 0) {
    if (filters.excludeTags.some((t) => serverConfig.tags.includes(t))) {
      return false;
    }
  }

  if (filters.includeTools && filters.includeTools.length > 0) {
    if (!matchesAnyGlob(filters.includeTools, tool.namespacedName)) {
      return false;
    }
  }
  if (filters.excludeTools && filters.excludeTools.length > 0) {
    if (matchesAnyGlob(filters.excludeTools, tool.namespacedName)) {
      return false;
    }
  }

  return true;
}

function ruleIdentifier(rule: PolicyRule, index: number): string {
  return rule.name ?? `[${index}]:${rule.effect}:${rule.tools[0] ?? "*"}`;
}

/**
 * Evaluate policy rules for a tool call. Returns { allowed, reason, evaluated }.
 *
 * Rules are evaluated in order; first match wins.
 * If no rules match, the call is ALLOWED (default-allow).
 *
 * `evaluated` lists the identifiers of every rule whose server/tag preconditions
 * matched this call — i.e., every rule the engine actually compared tool patterns
 * against, including the deciding rule. Rules excluded by server or tag scope are
 * not listed. This is what gets recorded in the `policies_evaluated` audit column.
 *
 * Tool patterns match against the NAMESPACED name (e.g., 'github__create_issue').
 */
export function evaluatePolicy(
  toolName: string,
  serverName: string,
  serverConfig: UpstreamServerConfig,
  policies: PolicyRule[],
): { allowed: boolean; reason?: string; evaluated: string[] } {
  const evaluated: string[] = [];

  for (let i = 0; i < policies.length; i++) {
    const rule = policies[i];

    if (rule.servers && rule.servers.length > 0) {
      if (!rule.servers.includes(serverName)) continue;
    }
    if (rule.tags && rule.tags.length > 0) {
      if (!rule.tags.some((t) => serverConfig.tags.includes(t))) continue;
    }

    evaluated.push(ruleIdentifier(rule, i));

    if (!matchesAnyGlob(rule.tools, toolName)) continue;

    if (rule.effect === "deny") {
      return {
        allowed: false,
        reason: `Denied by policy: ${rule.tools.join(", ")}`,
        evaluated,
      };
    }
    return {
      allowed: true,
      reason: `Allowed by policy: ${rule.tools.join(", ")}`,
      evaluated,
    };
  }

  return { allowed: true, evaluated };
}
