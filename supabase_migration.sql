-- UAE Tax & Accounting System
-- SAFE SCHEMA INITIALIZATION FOR A NEW/ISOLATED DATABASE ONLY.
-- DO NOT run blindly against an existing production database.
-- Never drops, truncates, renames, or deletes existing financial data.

CREATE TABLE IF NOT EXISTS public.users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE,
  password TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'Clerk' CHECK (role IN ('Owner', 'Clerk')),
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.transactions (
  id BIGSERIAL PRIMARY KEY,
  transaction_type TEXT NOT NULL CHECK (transaction_type IN ('sales', 'purchases')),
  transaction_date DATE NOT NULL,
  invoice_no TEXT NOT NULL DEFAULT '',
  party_name TEXT NOT NULL,
  trn TEXT NOT NULL DEFAULT '000000000000000',
  amount_before_tax NUMERIC(15, 2) NOT NULL DEFAULT 0.00,
  vat_rate NUMERIC(6, 4) NOT NULL DEFAULT 0.05,
  vat_amount NUMERIC(15, 2) NOT NULL DEFAULT 0.00,
  amount_with_tax NUMERIC(15, 2) NOT NULL DEFAULT 0.00,
  tax_mode TEXT NOT NULL DEFAULT 'inclusive' CHECK (tax_mode IN ('inclusive', 'exclusive', 'exempt')),
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_transactions_type_date
  ON public.transactions(transaction_type, transaction_date DESC);
CREATE INDEX IF NOT EXISTS idx_transactions_party
  ON public.transactions(party_name);
CREATE INDEX IF NOT EXISTS idx_transactions_trn
  ON public.transactions(trn);

CREATE TABLE IF NOT EXISTS public.suppliers (
  id BIGSERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  trn TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_suppliers_trn_unique
  ON public.suppliers(trn);

CREATE TABLE IF NOT EXISTS public.settings (
  id TEXT PRIMARY KEY,
  value JSONB NOT NULL DEFAULT '[]'::jsonb,
  updated_at TIMESTAMPTZ DEFAULT now()
);

ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.suppliers ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.settings ENABLE ROW LEVEL SECURITY;

-- No public/anonymous policies are created here.
-- The Cloud Run server uses the server-side Supabase credential.
-- Configure narrowly-scoped policies only if a separate direct client is intentionally introduced.

CREATE OR REPLACE FUNCTION public.import_transactions_batch(rows JSONB)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  inserted_count INT := 0;
  elem JSONB;
BEGIN
  IF jsonb_typeof(rows) <> 'array' THEN
    RAISE EXCEPTION 'rows must be a JSON array';
  END IF;

  FOR elem IN SELECT * FROM jsonb_array_elements(rows)
  LOOP
    IF elem->>'transaction_type' NOT IN ('sales', 'purchases') THEN
      RAISE EXCEPTION 'Invalid transaction_type';
    END IF;

    IF elem->>'tax_mode' NOT IN ('inclusive', 'exclusive', 'exempt') THEN
      RAISE EXCEPTION 'Invalid tax_mode';
    END IF;

    INSERT INTO public.transactions (
      transaction_type,
      transaction_date,
      invoice_no,
      party_name,
      trn,
      amount_before_tax,
      vat_rate,
      vat_amount,
      amount_with_tax,
      tax_mode
    ) VALUES (
      elem->>'transaction_type',
      (elem->>'transaction_date')::date,
      COALESCE(elem->>'invoice_no', ''),
      COALESCE(elem->>'party_name', 'UNKNOWN_PARTY'),
      COALESCE(elem->>'trn', '000000000000000'),
      (elem->>'amount_before_tax')::numeric,
      (elem->>'vat_rate')::numeric,
      (elem->>'vat_amount')::numeric,
      (elem->>'amount_with_tax')::numeric,
      elem->>'tax_mode'
    );

    inserted_count := inserted_count + 1;
  END LOOP;

  RETURN jsonb_build_object('success', true, 'inserted_count', inserted_count);
EXCEPTION
  WHEN OTHERS THEN
    RAISE EXCEPTION 'Atomic batch import failed: %', SQLERRM;
END;
$$;

-- The RPC is server-only. Supabase client roles must not be able to invoke financial imports directly.
REVOKE ALL ON FUNCTION public.import_transactions_batch(JSONB) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.import_transactions_batch(JSONB) FROM anon;
REVOKE ALL ON FUNCTION public.import_transactions_batch(JSONB) FROM authenticated;
GRANT EXECUTE ON FUNCTION public.import_transactions_batch(JSONB) TO service_role;

-- No default users are inserted.
-- Create the first production Owner through a controlled bootstrap process.
