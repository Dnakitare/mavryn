import type { NamespacedTool } from "../proxy/upstream.js";
import type { UpstreamServerConfig } from "../config.js";

interface ScoredResult {
  tool: NamespacedTool;
  score: number;
  signals: string[];
}

function tokenize(text: string): string[] {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9_\s]/g, " ")
    .split(/[\s_]+/)
    .filter((w) => w.length > 2); // min 3 chars to avoid substring noise
}

function termFrequency(text: string): Map<string, number> {
  const tf = new Map<string, number>();
  for (const word of tokenize(text)) {
    tf.set(word, (tf.get(word) ?? 0) + 1);
  }
  return tf;
}

function buildIdf(tools: NamespacedTool[]): Map<string, number> {
  const docCount = tools.length;
  const docFreq = new Map<string, number>();

  for (const tool of tools) {
    const text = `${tool.namespacedName} ${tool.tool.description ?? ""}`;
    const uniqueWords = new Set(tokenize(text));
    for (const word of uniqueWords) {
      docFreq.set(word, (docFreq.get(word) ?? 0) + 1);
    }
  }

  const idf = new Map<string, number>();
  for (const [word, freq] of docFreq) {
    idf.set(word, Math.log((docCount + 1) / (freq + 1)) + 1);
  }
  return idf;
}

export class ToolRouter {
  private tools: NamespacedTool[] = [];
  private serverConfigs: Map<string, UpstreamServerConfig> = new Map();
  private idf: Map<string, number> = new Map();
  private toolVectors: Map<string, Map<string, number>> = new Map();

  setTools(tools: NamespacedTool[], serverConfigs: Map<string, UpstreamServerConfig>): void {
    this.tools = tools;
    this.serverConfigs = serverConfigs;
    this.idf = buildIdf(tools);

    this.toolVectors.clear();
    for (const tool of tools) {
      const text = `${tool.namespacedName} ${tool.originalName} ${tool.tool.description ?? ""}`;
      const tf = termFrequency(text);
      const tfidf = new Map<string, number>();
      for (const [term, freq] of tf) {
        tfidf.set(term, freq * (this.idf.get(term) ?? 1));
      }
      this.toolVectors.set(tool.namespacedName, tfidf);
    }
  }

  search(query: string, opts?: { server?: string; tag?: string; limit?: number }): ScoredResult[] {
    const limit = opts?.limit ?? 20;
    const queryTrimmed = query.trim();

    // Empty or whitespace-only query returns nothing
    if (queryTrimmed.length === 0) return [];

    const queryTokens = tokenize(queryTrimmed);
    const queryTf = termFrequency(queryTrimmed);
    const queryLower = queryTrimmed.toLowerCase();
    const results: ScoredResult[] = [];

    for (const tool of this.tools) {
      if (opts?.server && tool.upstream !== opts.server) continue;
      if (opts?.tag) {
        const sc = this.serverConfigs.get(tool.upstream);
        if (!sc?.tags.includes(opts.tag)) continue;
      }

      const signals: string[] = [];
      let score = 0;

      const nameLower = tool.namespacedName.toLowerCase();
      const origLower = tool.originalName.toLowerCase();

      // 1. Exact name match (strongest signal)
      if (nameLower === queryLower || origLower === queryLower) {
        score += 50;
        signals.push("exact_name_match");
      } else if (nameLower.includes(queryLower) || origLower.includes(queryLower)) {
        score += 20;
        signals.push("partial_name_match");
      }

      // 2. TF-IDF cosine similarity
      const toolVec = this.toolVectors.get(tool.namespacedName);
      if (toolVec && queryTf.size > 0) {
        let dotProduct = 0;
        let queryMag = 0;
        let toolMag = 0;

        for (const [term, qFreq] of queryTf) {
          const qWeight = qFreq * (this.idf.get(term) ?? 1);
          const tWeight = toolVec.get(term) ?? 0;
          dotProduct += qWeight * tWeight;
          queryMag += qWeight * qWeight;
        }
        for (const tWeight of toolVec.values()) {
          toolMag += tWeight * tWeight;
        }

        if (queryMag > 0 && toolMag > 0) {
          const cosine = dotProduct / (Math.sqrt(queryMag) * Math.sqrt(toolMag));
          const tfidfScore = cosine * 30;
          if (tfidfScore > 0.5) {
            score += tfidfScore;
            signals.push(`tfidf:${cosine.toFixed(3)}`);
          }
        }
      }

      // 3. Word boundary hits in description (only for tokens >= 3 chars)
      const desc = (tool.tool.description ?? "").toLowerCase();
      const descTokens = new Set(tokenize(desc));
      for (const token of queryTokens) {
        if (descTokens.has(token)) {
          score += 2;
        }
      }

      if (score > 0) {
        results.push({ tool, score, signals });
      }
    }

    return results
      .sort((a, b) => b.score - a.score)
      .slice(0, limit);
  }
}
