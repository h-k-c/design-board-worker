-- AI call failure log. We only persist FAILED calls (parse errors, HTTP errors,
-- timeouts) — successful calls are not stored. Written asynchronously.
CREATE TABLE IF NOT EXISTS ai_call_logs (
  id          TEXT PRIMARY KEY,
  created_at  TEXT NOT NULL,
  user_id     TEXT,
  source      TEXT,          -- 'client' | 'worker'
  mode        TEXT,          -- component-fill / page-skeleton / page-restyle / ...
  component   TEXT,          -- component name when applicable
  instruction TEXT,          -- edit instruction when applicable
  error       TEXT,          -- error message
  raw_excerpt TEXT,          -- first chars of the model's raw output (for debugging)
  context     TEXT           -- optional JSON blob with extra fields
);
CREATE INDEX IF NOT EXISTS idx_ai_logs_created ON ai_call_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_ai_logs_user ON ai_call_logs(user_id, created_at);
