-- Multi-user data isolation.
-- Every per-user table gets a user_id (= JWT `sub` = username). Existing rows
-- are backfilled to the only current user ('openorange') so their board, pages
-- and settings are preserved. After this, all handlers scope reads/writes by the
-- logged-in user.

-- cards: one board per user.
ALTER TABLE cards ADD COLUMN user_id TEXT;
UPDATE cards SET user_id = 'openorange' WHERE user_id IS NULL;
CREATE INDEX IF NOT EXISTS idx_cards_user ON cards (user_id);

-- board_state: was a singleton (id=1). Now one row per user.
ALTER TABLE board_state ADD COLUMN user_id TEXT;
UPDATE board_state SET user_id = 'openorange' WHERE user_id IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_board_state_user ON board_state (user_id);

-- app_settings: rebuild with a composite (user_id, key) primary key so each
-- user has their own provider_settings / ui_settings.
ALTER TABLE app_settings RENAME TO app_settings_old;
CREATE TABLE app_settings (
  user_id TEXT NOT NULL,
  key TEXT NOT NULL,
  value TEXT NOT NULL,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (user_id, key)
);
INSERT INTO app_settings (user_id, key, value, updated_at)
  SELECT 'openorange', key, value, COALESCE(updated_at, CURRENT_TIMESTAMP) FROM app_settings_old;
DROP TABLE app_settings_old;

-- Generated pages ownership chain.
ALTER TABLE generated_page_groups ADD COLUMN user_id TEXT;
UPDATE generated_page_groups SET user_id = 'openorange' WHERE user_id IS NULL;
CREATE INDEX IF NOT EXISTS idx_ggroups_user ON generated_page_groups (user_id);

ALTER TABLE generated_pages ADD COLUMN user_id TEXT;
UPDATE generated_pages SET user_id = 'openorange' WHERE user_id IS NULL;
CREATE INDEX IF NOT EXISTS idx_gpages_user ON generated_pages (user_id);

ALTER TABLE generated_page_versions ADD COLUMN user_id TEXT;
UPDATE generated_page_versions SET user_id = 'openorange' WHERE user_id IS NULL;
CREATE INDEX IF NOT EXISTS idx_gversions_user ON generated_page_versions (user_id);

ALTER TABLE page_edit_events ADD COLUMN user_id TEXT;
UPDATE page_edit_events SET user_id = 'openorange' WHERE user_id IS NULL;

-- Assets / images: associate with the owner. Access stays via capability URL
-- (random UUID), but per-user scoping prevents cross-user orphan cleanup from
-- soft-deleting another user's assets.
ALTER TABLE assets ADD COLUMN user_id TEXT;
UPDATE assets SET user_id = 'openorange' WHERE user_id IS NULL;
CREATE INDEX IF NOT EXISTS idx_assets_user ON assets (user_id);

ALTER TABLE images ADD COLUMN user_id TEXT;
UPDATE images SET user_id = 'openorange' WHERE user_id IS NULL;
