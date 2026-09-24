-- SEVENGATES platform schema — auto-applied on server startup (safe to re-run)

CREATE TABLE IF NOT EXISTS customers (
  id SERIAL PRIMARY KEY,
  phone TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  first_contact_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_contact_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  notes TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS technicians (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  phone TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  specialties TEXT[] NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'متاح', -- متاح / غير متاح / إجازة
  active BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS catalog_items (
  id SERIAL PRIMARY KEY,
  category TEXT NOT NULL, -- 'device' or 'service_type'
  name TEXT NOT NULL,
  active BOOLEAN NOT NULL DEFAULT true,
  sort_order INT NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (category, name)
);

CREATE TABLE IF NOT EXISTS orders (
  id SERIAL PRIMARY KEY,
  customer_phone TEXT NOT NULL REFERENCES customers(phone),
  name TEXT NOT NULL,
  phone TEXT NOT NULL,
  device TEXT NOT NULL,
  service TEXT NOT NULL,
  description TEXT NOT NULL,
  address TEXT NOT NULL DEFAULT '',
  location_url TEXT NOT NULL DEFAULT '',
  photo_data TEXT,
  status TEXT NOT NULL DEFAULT 'قيد المراجعة',
  is_waiting_list BOOLEAN NOT NULL DEFAULT false,
  waiting_reason TEXT NOT NULL DEFAULT '',
  assigned_to TEXT NOT NULL DEFAULT '',
  technician_id INT REFERENCES technicians(id),
  assigned_at TIMESTAMPTZ,
  notes TEXT NOT NULL DEFAULT '',
  payment_method TEXT NOT NULL DEFAULT 'cash',
  source TEXT NOT NULL DEFAULT 'website',
  tracking_token TEXT UNIQUE,
  invoice_photo TEXT,
  invoice_amount NUMERIC(10,2),
  completed_at TIMESTAMPTZ,
  rating INT,
  review_text TEXT NOT NULL DEFAULT '',
  review_public BOOLEAN NOT NULL DEFAULT true,
  complaint_text TEXT NOT NULL DEFAULT '',
  complaint_status TEXT NOT NULL DEFAULT '', -- '' / جديدة / قيد المراجعة / تم الحل
  complaint_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- backfill columns for databases created before this update
ALTER TABLE orders ADD COLUMN IF NOT EXISTS is_waiting_list BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS waiting_reason TEXT NOT NULL DEFAULT '';
ALTER TABLE orders ADD COLUMN IF NOT EXISTS technician_id INT REFERENCES technicians(id);
ALTER TABLE orders ADD COLUMN IF NOT EXISTS tracking_token TEXT;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS invoice_photo TEXT;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS invoice_amount NUMERIC(10,2);
ALTER TABLE orders ADD COLUMN IF NOT EXISTS completed_at TIMESTAMPTZ;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS rating INT;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS review_text TEXT NOT NULL DEFAULT '';
ALTER TABLE orders ADD COLUMN IF NOT EXISTS review_public BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS complaint_text TEXT NOT NULL DEFAULT '';
ALTER TABLE orders ADD COLUMN IF NOT EXISTS complaint_status TEXT NOT NULL DEFAULT '';
ALTER TABLE orders ADD COLUMN IF NOT EXISTS complaint_at TIMESTAMPTZ;

-- backfill tracking tokens for any pre-existing rows, then enforce uniqueness
UPDATE orders SET tracking_token = UPPER(SUBSTRING(MD5(id::text || random()::text), 1, 8)) WHERE tracking_token IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_orders_tracking_token ON orders (tracking_token);

CREATE INDEX IF NOT EXISTS idx_orders_created_at ON orders (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_orders_customer_phone ON orders (customer_phone);
CREATE INDEX IF NOT EXISTS idx_orders_status ON orders (status);
CREATE INDEX IF NOT EXISTS idx_orders_technician_id ON orders (technician_id);

-- seed default catalog (only if empty)
INSERT INTO catalog_items (category, name, sort_order)
SELECT * FROM (VALUES
  ('device', 'تكييف', 1),
  ('device', 'ثلاجة', 2),
  ('device', 'غسالة', 3),
  ('device', 'سخان', 4),
  ('device', 'فرن', 5),
  ('device', 'تمديدات كهرباء', 6),
  ('device', 'أخرى', 7)
) AS v(category, name, sort_order)
WHERE NOT EXISTS (SELECT 1 FROM catalog_items WHERE category = 'device');

INSERT INTO catalog_items (category, name, sort_order)
SELECT * FROM (VALUES
  ('service_type', 'صيانة', 1),
  ('service_type', 'تركيب', 2),
  ('service_type', 'تجديد', 3),
  ('service_type', 'استبدال', 4)
) AS v(category, name, sort_order)
WHERE NOT EXISTS (SELECT 1 FROM catalog_items WHERE category = 'service_type');

CREATE INDEX IF NOT EXISTS idx_orders_created_at ON orders (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_orders_customer_phone ON orders (customer_phone);
CREATE INDEX IF NOT EXISTS idx_orders_status ON orders (status);
