-- Who is allowed to use the shared Vertex AI provider (it spends the owner's
-- $300 credit, so it's gated by an allowlist + a per-user daily request cap).
-- Seed the only current user. New users are NOT allowed by default — add a row
-- here (or later via an admin UI) to grant access.
CREATE TABLE IF NOT EXISTS vertex_access (
  user_id TEXT PRIMARY KEY,
  enabled INTEGER NOT NULL DEFAULT 1,
  daily_limit INTEGER NOT NULL DEFAULT 500,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO vertex_access (user_id, enabled, daily_limit)
  VALUES ('openorange', 1, 2000)
  ON CONFLICT(user_id) DO NOTHING;

-- Per-user, per-day Vertex call counter for the daily cap.
CREATE TABLE IF NOT EXISTS vertex_usage (
  user_id TEXT NOT NULL,
  day TEXT NOT NULL,
  count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (user_id, day)
);
