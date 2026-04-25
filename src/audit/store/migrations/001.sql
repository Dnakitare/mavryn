CREATE TABLE IF NOT EXISTS events (
  seq             INTEGER PRIMARY KEY AUTOINCREMENT,
  id              TEXT NOT NULL UNIQUE,
  timestamp       TEXT NOT NULL,
  session_id      TEXT,
  server_name     TEXT,
  agent_id        TEXT,
  tool_name       TEXT NOT NULL,
  tool_arguments  TEXT NOT NULL CHECK(length(tool_arguments) <= 1048576),
  tool_annotations TEXT,
  policy_decision TEXT NOT NULL DEFAULT 'allow',
  policy_reason   TEXT,
  policies_evaluated TEXT,
  result_status   TEXT CHECK(result_status IN ('success', 'error', 'blocked') OR result_status IS NULL),
  result_summary  TEXT,
  result_latency_ms INTEGER CHECK(result_latency_ms >= 0 OR result_latency_ms IS NULL),
  user_id         TEXT,
  source_tag      TEXT,
  prompt_context  TEXT,
  turn_id         TEXT,
  assistant_message TEXT,
  system_prompt_hash TEXT,
  meta            TEXT,
  prev_hash       TEXT UNIQUE,
  event_hash      TEXT NOT NULL UNIQUE,
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_tool ON events(tool_name);
CREATE INDEX IF NOT EXISTS idx_events_decision ON events(policy_decision);
CREATE INDEX IF NOT EXISTS idx_events_user ON events(user_id);
CREATE INDEX IF NOT EXISTS idx_events_source ON events(source_tag);
CREATE INDEX IF NOT EXISTS idx_events_turn ON events(turn_id);
