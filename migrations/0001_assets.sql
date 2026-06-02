CREATE TABLE IF NOT EXISTS assets (
  id TEXT PRIMARY KEY,
  r2_key TEXT NOT NULL UNIQUE,
  public_url TEXT NOT NULL,
  filename TEXT,
  content_type TEXT,
  size INTEGER,
  width INTEGER,
  height INTEGER,
  sha256 TEXT,
  etag TEXT,
  source_image_id TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  deleted_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_assets_r2_key ON assets (r2_key);
CREATE INDEX IF NOT EXISTS idx_assets_source_image_id ON assets (source_image_id);
CREATE INDEX IF NOT EXISTS idx_assets_deleted_at ON assets (deleted_at);
