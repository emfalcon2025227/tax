-- ============================================================================
-- Accounting & Tax Analysis System - Suppliers Table Migration Script
-- Data Source: Extracted strictly from Client Google Sheet (19 Real Records)
-- Developer: م/ محمود محمد | mahmoud.m@sdi.ae
-- ============================================================================

-- 1. Create the suppliers table if it does not already exist
CREATE TABLE IF NOT EXISTS suppliers (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    trn VARCHAR(15) NOT NULL CHECK (trn ~ '^[0-9]{15}$'),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT unique_supplier_trn UNIQUE (trn)
);

-- 2. Create index for rapid lookup during interactive data entry
CREATE INDEX IF NOT EXISTS idx_suppliers_name ON suppliers(name);
CREATE INDEX IF NOT EXISTS idx_suppliers_trn ON suppliers(trn);

-- 3. Populate with STRICTLY the 19 Real Records extracted from Google Sheet
-- Using ON CONFLICT DO UPDATE to ensure idempotency when re-running migrations
INSERT INTO suppliers (name, trn) VALUES
('AL HAJJAN FOODSTUFF TRADING', '100023718800003'),
('NATIONAL DAIRY L.L.C', '100303591000003'),
('Talabat', '100000978500003'),
('SEWA', '100394961500003'),
('JOINT TRADING L.L.C SP BR', '105037098800003'),
('AL TAYEB INTERNATIONAL GENERAL TRADING', '100228723000003'),
('Bait Al Bahar Household TR. L.L.C', '100003845300003'),
('PAKYZ AL AKWAB TRADING', '100461454900003'),
('NATIONAL MARKETING', '100300236500003'),
('AL SAFA WATER TREATMENT CO LLC', '100346206400003'),
('AL ZAHMI TRADING EST', '100226647400003'),
('FEDERAL FOODS L.L.C', '100283803300003'),
('EMIRATES GALLERY DISCOUNTS', '100446141200003'),
('HOTPACK PACKAGING LLC', '100068415900003'),
('MHP FOOD TRADING L.L.C', '100356894400003'),
('AL MADINA HYPERMAKET L.L.C. BR1', '100303752800003'),
('NETWORK INTERNATIONAL LLC', '100204231300003'),
('AL SAFI DRINKING WATER PURIFICATION', '100230544700003'),
('NESTO HYPER MARKET LLC', '100247587700003')
ON CONFLICT (trn) DO UPDATE 
SET name = EXCLUDED.name;
