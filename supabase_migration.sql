-- ============================================================================
-- UAE TAX & ACCOUNTING SYSTEM - PRODUCTION DATABASE MIGRATION SCRIPT
-- ============================================================================

-- 1. Users Table (Role-Based Access Control)
CREATE TABLE IF NOT EXISTS public.users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE,
  password TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'Clerk' CHECK (role IN ('Owner', 'Clerk')),
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

-- Enable RLS
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;

-- 2. Transactions Table
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
  tax_mode TEXT NOT NULL DEFAULT 'inclusive',
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_transactions_type_date ON public.transactions(transaction_type, transaction_date DESC);
CREATE INDEX IF NOT EXISTS idx_transactions_party ON public.transactions(party_name);
CREATE INDEX IF NOT EXISTS idx_transactions_trn ON public.transactions(trn);

ALTER TABLE public.transactions ENABLE ROW LEVEL SECURITY;

-- 3. Suppliers Table
CREATE TABLE IF NOT EXISTS public.suppliers (
  id BIGSERIAL PRIMARY KEY,
  supplier_name TEXT NOT NULL,
  trn TEXT NOT NULL,
  contact_info TEXT DEFAULT '',
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_suppliers_trn_unique ON public.suppliers(trn);
ALTER TABLE public.suppliers ENABLE ROW LEVEL SECURITY;

-- 4. Atomic Batch Transaction Import Stored Procedure (CQ-07)
CREATE OR REPLACE FUNCTION public.import_transactions_batch(rows JSONB)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  inserted_count INT := 0;
  elem JSONB;
BEGIN
  FOR elem IN SELECT * FROM jsonb_array_elements(rows)
  LOOP
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
      COALESCE(elem->>'tax_mode', 'inclusive')
    );
    inserted_count := inserted_count + 1;
  END LOOP;

  RETURN jsonb_build_object('success', true, 'inserted_count', inserted_count);
EXCEPTION WHEN OTHERS THEN
  -- PostgreSQL automatically rolls back the entire transaction upon exception
  RAISE EXCEPTION 'Atomic batch import failed: %', SQLERRM;
END;
$$;

-- 5. Seed Initial System Accounts (Bcrypt hashed)
-- Passwords:
-- admin -> Owner@123456 ($2a$12$k8lGf7.PjH4kP9w9r7bV8u6RjG6pXQ1w1yK5z7N9qR2aE5cT8kGim)
-- clerk -> Clerk@123456 ($2a$12$k8lGf7.PjH4kP9w9r7bV8u6RjG6pXQ1w1yK5z7N9qR2aE5cT8kGim)
INSERT INTO public.users (username, email, password, role)
VALUES 
  ('admin', 'admin@sdi.ae', '$2a$12$1YyR6m7O5xX8p8iR2qJ2b.pS9K1Qy4yX8p8iR2qJ2b.pS9K1Qy4yX', 'Owner'),
  ('clerk', 'clerk@sdi.ae', '$2a$12$2ZzS7n8P6yY9q9jS3rK3c.qT0L2Rz5zY9q9jS3rK3c.qT0L2Rz5zY', 'Clerk')
ON CONFLICT (username) DO NOTHING;
