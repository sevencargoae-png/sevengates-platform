// SEVENGATES platform — Express + Postgres backend
// Serves the public customer site, the staff dashboard, and the JSON API.

const path = require('path');
const fs = require('fs');
const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const JWT_SECRET = process.env.JWT_SECRET || '';
const COOKIE_NAME = 'sg_token';

if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL is not set. Add the Postgres connection string as an environment variable.');
}
if (!ADMIN_PASSWORD) {
  console.warn('WARNING: ADMIN_PASSWORD is not set — the staff dashboard cannot be logged into until it is.');
}
if (!JWT_SECRET) {
  console.warn('WARNING: JWT_SECRET is not set — using an insecure fallback. Set a real secret in production.');
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('localhost')
    ? false
    : { rejectUnauthorized: false },
});

async function ensureSchema() {
  const schemaPath = path.join(__dirname, 'db', 'schema.sql');
  const sql = fs.readFileSync(schemaPath, 'utf8');
  await pool.query(sql);
  console.log('Database schema ready.');
}

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());

// ---------- auth helpers ----------
function signToken() {
  return jwt.sign({ role: 'staff' }, JWT_SECRET || 'insecure-dev-secret', { expiresIn: '12h' });
}
function requireStaff(req, res, next) {
  const token = req.cookies[COOKIE_NAME];
  if (!token) return res.status(401).json({ error: 'unauthenticated' });
  try {
    jwt.verify(token, JWT_SECRET || 'insecure-dev-secret');
    next();
  } catch (e) {
    res.status(401).json({ error: 'unauthenticated' });
  }
}

// ---------- phone helper ----------
function normPhone(raw) {
  let d = String(raw || '').replace(/[^0-9]/g, '');
  if (d.startsWith('966') && d.length === 12) d = '0' + d.slice(3);
  if (d.startsWith('20') && d.length === 12) d = '0' + d.slice(2);
  if (d.length === 9 && d[0] !== '0') d = '0' + d;
  return d;
}

// ---------- public API ----------
app.post('/api/orders', async (req, res) => {
  try {
    const b = req.body || {};
    const name = String(b.name || '').trim();
    const phone = normPhone(b.phone);
    const device = String(b.device || '').trim();
    const service = String(b.service || '').trim();
    const description = String(b.description || '').trim();
    const address = String(b.address || '').trim();
    const locationUrl = String(b.locationUrl || '').trim();
    const photoData = typeof b.photoData === 'string' ? b.photoData : null;

    if (!name || !phone || !device || !service || !description) {
      return res.status(400).json({ error: 'missing_fields' });
    }
    if (photoData && photoData.length > 6_000_000) {
      return res.status(400).json({ error: 'photo_too_large' });
    }

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const existing = await client.query('SELECT phone FROM customers WHERE phone = $1', [phone]);
      if (existing.rowCount === 0) {
        await client.query(
          'INSERT INTO customers (phone, name, first_contact_at, last_contact_at) VALUES ($1, $2, now(), now())',
          [phone, name]
        );
      } else {
        await client.query(
          'UPDATE customers SET name = $2, last_contact_at = now() WHERE phone = $1',
          [phone, name]
        );
      }
      const orderResult = await client.query(
        `INSERT INTO orders (customer_phone, name, phone, device, service, description, address, location_url, photo_data, status, source)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'قيد المراجعة','website')
         RETURNING id, created_at`,
        [phone, name, phone, device, service, description, address, locationUrl, photoData]
      );
      await client.query('COMMIT');
      res.json({ ok: true, orderId: orderResult.rows[0].id });
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  } catch (err) {
    console.error('POST /api/orders failed:', err);
    res.status(500).json({ error: 'server_error' });
  }
});

// ---------- staff auth ----------
app.post('/api/staff/login', (req, res) => {
  const { password } = req.body || {};
  if (!ADMIN_PASSWORD || password !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'invalid_password' });
  }
  const token = signToken();
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 12 * 60 * 60 * 1000,
  });
  res.json({ ok: true });
});
app.post('/api/staff/logout', (req, res) => {
  res.clearCookie(COOKIE_NAME);
  res.json({ ok: true });
});
app.get('/api/staff/me', (req, res) => {
  const token = req.cookies[COOKIE_NAME];
  if (!token) return res.json({ authenticated: false });
  try {
    jwt.verify(token, JWT_SECRET || 'insecure-dev-secret');
    res.json({ authenticated: true });
  } catch (e) {
    res.json({ authenticated: false });
  }
});

// ---------- staff API (protected) ----------
app.get('/api/staff/orders', requireStaff, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM orders ORDER BY created_at DESC LIMIT 1000');
    res.json({ orders: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

app.patch('/api/staff/orders/:id', requireStaff, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ error: 'invalid_id' });
    const allowed = ['status', 'assignedTo', 'notes'];
    const fieldMap = { status: 'status', assignedTo: 'assigned_to', notes: 'notes' };
    const sets = [];
    const values = [];
    let i = 1;
    for (const key of allowed) {
      if (Object.prototype.hasOwnProperty.call(req.body, key)) {
        sets.push(`${fieldMap[key]} = $${i}`);
        values.push(req.body[key]);
        i++;
      }
    }
    if (Object.prototype.hasOwnProperty.call(req.body, 'assignedTo') && req.body.assignedTo) {
      sets.push(`assigned_at = now()`);
    }
    if (sets.length === 0) return res.status(400).json({ error: 'no_fields' });
    sets.push('updated_at = now()');
    values.push(id);
    const sql = `UPDATE orders SET ${sets.join(', ')} WHERE id = $${i} RETURNING *`;
    const { rows } = await pool.query(sql, values);
    if (rows.length === 0) return res.status(404).json({ error: 'not_found' });
    res.json({ order: rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

app.get('/api/staff/customers', requireStaff, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT c.*, COALESCE(oc.orders_count, 0)::int AS orders_count
      FROM customers c
      LEFT JOIN (
        SELECT customer_phone, COUNT(*) AS orders_count FROM orders GROUP BY customer_phone
      ) oc ON oc.customer_phone = c.phone
      ORDER BY c.last_contact_at DESC
      LIMIT 1000
    `);
    res.json({ customers: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

// ---------- static pages ----------
app.use(express.static(path.join(__dirname, 'public')));

app.get('/staff', (req, res) => {
  const token = req.cookies[COOKIE_NAME];
  let authed = false;
  if (token) {
    try { jwt.verify(token, JWT_SECRET || 'insecure-dev-secret'); authed = true; } catch (e) {}
  }
  if (!authed) return res.redirect('/staff/login');
  res.sendFile(path.join(__dirname, 'views', 'dashboard.html'));
});
app.get('/staff/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'login.html'));
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

ensureSchema()
  .then(() => {
    app.listen(PORT, () => console.log(`SEVENGATES platform running on port ${PORT}`));
  })
  .catch((err) => {
    console.error('Failed to prepare database schema:', err);
    process.exit(1);
  });
