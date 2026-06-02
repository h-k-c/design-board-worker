CREATE TABLE IF NOT EXISTS generated_page_groups (
  id TEXT PRIMARY KEY, card_id TEXT, title TEXT, prompt_card_id TEXT,
  status TEXT DEFAULT 'active', current_page_id TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP, updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
  deleted_at TEXT
);
CREATE TABLE IF NOT EXISTS generated_pages (
  id TEXT PRIMARY KEY, group_id TEXT NOT NULL, slug TEXT, title TEXT, route_path TEXT,
  sort_order INTEGER DEFAULT 0, parent_page_id TEXT, current_version_id TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP, updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
  deleted_at TEXT
);
CREATE TABLE IF NOT EXISTS generated_page_versions (
  id TEXT PRIMARY KEY, page_id TEXT NOT NULL, version_no INTEGER NOT NULL,
  source_prompt TEXT, edit_instruction TEXT,
  html_r2_key TEXT, css_r2_key TEXT, js_r2_key TEXT,
  summary TEXT, created_by TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS page_edit_events (
  id TEXT PRIMARY KEY, page_id TEXT NOT NULL, from_version_id TEXT, to_version_id TEXT,
  operation TEXT, instruction TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_gpages_group ON generated_pages (group_id);
CREATE INDEX IF NOT EXISTS idx_gversions_page ON generated_page_versions (page_id);
CREATE INDEX IF NOT EXISTS idx_ggroups_deleted ON generated_page_groups (deleted_at);
