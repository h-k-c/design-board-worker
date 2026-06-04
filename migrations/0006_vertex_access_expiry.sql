-- vertex_access basic settings: enabled (能否调用) + expires_at (可用时间，到期时间)
-- + daily_limit (每日次数). expires_at NULL = 永久有效。
ALTER TABLE vertex_access ADD COLUMN expires_at TEXT;

-- Ensure the owner has open, non-expiring access.
UPDATE vertex_access SET enabled = 1, expires_at = NULL WHERE user_id = 'openorange';
