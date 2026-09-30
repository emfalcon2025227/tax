-- Persistent application settings for UAE Tax & Accounting System.
-- SAFE FOR NEW/ISOLATED DATABASES. Review against live schema before production use.

CREATE TABLE IF NOT EXISTS public.settings (
    id TEXT PRIMARY KEY,
    value JSONB NOT NULL DEFAULT '[]'::jsonb,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE public.settings ENABLE ROW LEVEL SECURITY;

-- Deliberately no public/anonymous read-write policy.
-- Production access is through the authenticated server-side backend.

INSERT INTO public.settings (id, value, updated_at)
VALUES
  ('report_recipients', '[]'::jsonb, NOW()),
  ('application_config', '{"default_vat_rate": 5.0}'::jsonb, NOW())
ON CONFLICT (id) DO NOTHING;
