-- ============================================================================
-- Accounting & Tax Analysis System - Settings Table Migration Script
-- Stores dynamic application settings such as report recipients and config
-- Developer: Eng. Mahmoud Mohamed | mahmoud.m@sdi.ae
-- ============================================================================

-- 1. Create the settings table if it does not already exist
CREATE TABLE IF NOT EXISTS settings (
    id TEXT PRIMARY KEY,
    value JSONB NOT NULL DEFAULT '[]'::jsonb,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2. Enable row level security (optional based on project configuration)
ALTER TABLE settings ENABLE ROW LEVEL SECURITY;

-- 3. Policy: Allow read and write with valid service role or anon key
CREATE POLICY "Allow public read-write for settings" ON settings
    FOR ALL
    USING (true)
    WITH CHECK (true);

-- 4. Seed default report recipients record
INSERT INTO settings (id, value, updated_at)
VALUES ('report_recipients', '[]'::jsonb, NOW())
ON CONFLICT (id) DO NOTHING;
