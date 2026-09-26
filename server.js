// SEVENGATES platform — Express + Postgres backend
// Serves the public customer site, the order-tracking page, the technician portal,
// the staff/admin dashboard, and the JSON API behind all of them.

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');

const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const JWT_SECRET = process.env.JWT_SECRET || '';
const STAFF_COOKIE = 'sg_token';
const TECH_COOKIE = 'sg_tech_token';

if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL is not set. Add the Postgres connection string as an environment variable.');
}
if (!ADMIN_PASSWORD) {
  console.warn('WARNING: ADMIN_PASSWORD is not set — the staff dashboard cannot be logged into until it is.');
}
if (!JWT_SECRET) {
  console.warn('WARNING: JWT_SECRET is not set — using an insecure fallback. Set a real secret in production.');
}

// ---------- WhatsApp notifications (Twilio) ----------
const TWILIO_ACCOUNT_SID = process.env.TWILIO_ACCOUNT_SID || '';
const TWILIO_AUTH_TOKEN = process.env.TWILIO_AUTH_TOKEN || '';
const TWILIO_WHATSAPP_FROM = process.env.TWILIO_WHATSAPP_FROM || ''; // e.g. 'whatsapp:+14155238886'
let twilioClient = null;
if (TWILIO_ACCOUNT_SID && TWILIO_AUTH_TOKEN) {
  try {
    twilioClient = require('twilio')(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN);
  } catch (e) {
    console.warn('WARNING: failed to initialize Twilio client:', e.message);
  }
} else {
  console.warn('WARNING: TWILIO_ACCOUNT_SID / TWILIO_AUTH_TOKEN not set — WhatsApp notifications are disabled.');
}
function phoneToWhatsApp(localPhone) {
  let d = String(localPhone || '').replace(/[^0-9]/g, '');
  // The business and its customers/technicians are UAE-based (see public/index.html's
  // address and the site's own contact number) — this used to prepend '20' (Egypt) here,
  // which would have sent every WhatsApp notification to the wrong country entirely.
  if (d.startsWith('0')) d = '971' + d.slice(1);
  return 'whatsapp:+' + d;
}
async function sendWhatsApp(toLocalPhone, message) {
  if (!twilioClient || !TWILIO_WHATSAPP_FROM || !toLocalPhone) return;
  try {
    await twilioClient.messages.create({
      from: TWILIO_WHATSAPP_FROM,
      to: phoneToWhatsApp(toLocalPhone),
      body: message,
    });
  } catch (err) {
    console.error('WhatsApp send failed:', err.message);
  }
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('localhost')
    ? false
    : { rejectUnauthorized: false },
});
// Without this handler, an idle pooled connection that drops (a brief network blip, the
// database restarting for maintenance, Render recycling the connection) throws an uncaught
// 'error' event and crashes the entire Node process — taking the whole site down instead of
// just that one query failing. Logging it here keeps the process alive; the pool reconnects
// on its own for the next query, and /healthz will report the outage in the meantime.
pool.on('error', (err) => {
  console.error('Unexpected error on idle database client:', err.message);
});

async function ensureSchema() {
  const schemaPath = path.join(__dirname, 'db', 'schema.sql');
  const sql = fs.readFileSync(schemaPath, 'utf8');
  await pool.query(sql);
  console.log('Database schema ready.');
}

const app = express();
app.disable('x-powered-by');
// Render sits in front of this service as a reverse proxy (TLS-terminating) — trust exactly
// one hop so req.secure / req.ip reflect the real client instead of the proxy.
app.set('trust proxy', 1);
app.use(helmet({
  // The site's pages use inline <script>/<style> throughout with no nonce system,
  // so a strict default CSP would break every page. Other helmet protections
  // (HSTS, X-Content-Type-Options, X-Frame-Options, etc.) stay on.
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
}));
app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());

// ---------- rate limiting ----------
// Stricter limiter for login endpoints (brute-force protection).
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'too_many_attempts' },
});
// Looser limiter for public-facing write endpoints (order submission, tracking, ratings, complaints).
const publicLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'too_many_requests' },
});

// ---------- health check (used by Render to detect a hung/broken deploy) ----------
// Deliberately placed before any auth/rate-limit middleware that could block it, and kept
// fast and dependency-light: it confirms the process can still reach the database, which is
// the one failure mode that would otherwise leave the site "up" but completely broken.
app.get('/healthz', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.status(200).json({ status: 'ok' });
  } catch (err) {
    console.error('Health check failed:', err.message);
    res.status(503).json({ status: 'error', error: 'db_unreachable' });
  }
});

// ---------- generic helpers ----------
function normPhone(raw) {
  let d = String(raw || '').replace(/[^0-9]/g, '');
  if (d.startsWith('971') && d.length === 12) d = '0' + d.slice(3); // UAE — the business's own country
  if (d.startsWith('966') && d.length === 12) d = '0' + d.slice(3);
  if (d.startsWith('20') && d.length === 12) d = '0' + d.slice(2);
  if (d.length === 9 && d[0] !== '0') d = '0' + d;
  return d;
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(password), salt, 64).toString('hex');
  return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [salt, hash] = stored.split(':');
  try {
    const hashBuffer = Buffer.from(hash, 'hex');
    const suppliedBuffer = crypto.scryptSync(String(password), salt, 64);
    if (hashBuffer.length !== suppliedBuffer.length) return false;
    return crypto.timingSafeEqual(hashBuffer, suppliedBuffer);
  } catch (e) {
    return false;
  }
}
function genTrackingToken() {
  return crypto.randomBytes(4).toString('hex').toUpperCase();
}

// ---------- generic app settings (currently: the staff-dashboard password, once changed
// from inside the dashboard instead of via the ADMIN_PASSWORD env var) ----------
async function getSetting(key) {
  const { rows } = await pool.query('SELECT value FROM app_settings WHERE key = $1', [key]);
  return rows.length ? rows[0].value : null;
}
async function setSetting(key, value) {
  await pool.query(
    `INSERT INTO app_settings (key, value, updated_at) VALUES ($1, $2, now())
     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
    [key, value]
  );
}
// The effective staff-dashboard password check: a password set from the dashboard's
// Settings tab (stored hashed in app_settings) always takes priority; until one is set,
// this falls back to the ADMIN_PASSWORD environment variable, exactly as before.
async function verifyStaffPassword(suppliedPassword) {
  const storedHash = await getSetting('admin_password_hash');
  if (storedHash) return verifyPassword(suppliedPassword, storedHash);
  return !!ADMIN_PASSWORD && suppliedPassword === ADMIN_PASSWORD;
}

// ---------- order status: allowed values, audit log, SLA ----------
const ORDER_STATUSES = ['قيد المراجعة', 'تمت الموافقة', 'جاري التنفيذ', 'مكتمل', 'قائمة انتظار', 'مرفوض'];

// Append a row to the immutable status-history audit log. Never update or delete from this table.
async function logHistory(orderId, oldStatus, newStatus, changedBy, req, opts) {
  opts = opts || {};
  try {
    await pool.query(
      `INSERT INTO order_status_history (order_id, old_status, new_status, changed_by, reason, flagged, flag_reason, ip_address)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [orderId, oldStatus || null, newStatus, changedBy, opts.reason || '', !!opts.flagged, opts.flagReason || '', (req && req.ip) || '']
    );
  } catch (err) {
    console.error('Failed to write order_status_history:', err.message);
  }
}

// A public-safe label for who made a change — never leaks staff/technician identity to a customer.
function publicActorLabel(changedBy) {
  if (!changedBy) return 'النظام';
  if (changedBy.startsWith('tech:')) return 'الفني';
  if (changedBy === 'staff' || changedBy === 'staff-override') return 'فريق SEVENGATES';
  if (changedBy === 'customer') return 'أنت';
  return 'النظام';
}

// Compute a human-readable delay flag for staff, based purely on timestamps already on the order.
const SLA_MS = {
  review: 2 * 60 * 60 * 1000,       // قيد المراجعة / قائمة انتظار: should be triaged within 2h
  techStart: 3 * 60 * 60 * 1000,    // تمت الموافقة: technician should start within 3h of assignment
  inProgress: 24 * 60 * 60 * 1000,  // جاري التنفيذ: should wrap up within 24h of assignment
  confirm: 48 * 60 * 60 * 1000,     // مكتمل: customer should confirm/rate within 48h
};
function computeSlaFlag(o, now) {
  now = now || Date.now();
  const status = o.status;
  if ((status === 'قيد المراجعة' || status === 'قائمة انتظار') && o.created_at) {
    if (now - new Date(o.created_at).getTime() > SLA_MS.review) return 'متأخر: بانتظار المراجعة/تعيين فني';
  } else if (status === 'تمت الموافقة' && o.assigned_at) {
    if (now - new Date(o.assigned_at).getTime() > SLA_MS.techStart) return 'متأخر: الفني لسه مبدأش التنفيذ';
  } else if (status === 'جاري التنفيذ' && o.assigned_at) {
    if (now - new Date(o.assigned_at).getTime() > SLA_MS.inProgress) return 'متأخر: التنفيذ طال عن المتوقع';
  } else if (status === 'مكتمل' && o.completed_at && !o.customer_confirmed_at && o.rating == null) {
    if (now - new Date(o.completed_at).getTime() > SLA_MS.confirm) return 'يحتاج تأكيد/متابعة مع العميل';
  }
  return null;
}

function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET || 'insecure-dev-secret', { expiresIn: '12h' });
}
function verifyJwt(token) {
  try {
    return jwt.verify(token, JWT_SECRET || 'insecure-dev-secret');
  } catch (e) {
    return null;
  }
}
function requireStaff(req, res, next) {
  const payload = verifyJwt(req.cookies[STAFF_COOKIE]);
  if (!payload || payload.role !== 'staff') return res.status(401).json({ error: 'unauthenticated' });
  next();
}
async function requireTech(req, res, next) {
  const payload = verifyJwt(req.cookies[TECH_COOKIE]);
  if (!payload || payload.role !== 'tech') return res.status(401).json({ error: 'unauthenticated' });
  try {
    const { rows } = await pool.query('SELECT * FROM technicians WHERE id = $1 AND active = true', [payload.id]);
    if (rows.length === 0) return res.status(401).json({ error: 'unauthenticated' });
    req.technician = rows[0];
    next();
  } catch (e) {
    res.status(500).json({ error: 'server_error' });
  }
}

// Decide whether a device/service is currently offerable.
// - if the admin explicitly disabled the catalog item -> unavailable (reason 'disabled')
// - if technicians exist for that specialty but none are currently 'متاح' -> unavailable (reason 'no_technician')
// - if no technician has ever been assigned that specialty (not configured yet) -> treat as available
async function computeAvailability(device) {
  const item = await pool.query(
    "SELECT active FROM catalog_items WHERE category = 'device' AND name = $1",
    [device]
  );
  if (item.rowCount > 0 && item.rows[0].active === false) {
    return { available: false, reason: 'disabled' };
  }
  const total = await pool.query(
    'SELECT COUNT(*)::int AS c FROM technicians WHERE active = true AND $1 = ANY(specialties)',
    [device]
  );
  if (total.rows[0].c > 0) {
    const free = await pool.query(
    "SELECT COUNT(*)::int AS c FROM technicians WHERE active = true AND status = 'متاح' AND $1 = ANY(specialties)",
      [device]
    );
    if (free.rows[0].c === 0) return { available: false, reason: 'no_technician' };
  }
  return { available: true, reason: '' };
}

function publicOrderView(o) {
  return {
    id: o.id,
    trackingToken: o.tracking_token,
    device: o.device,
    service: o.service,
    description: o.description,
    status: o.status,
    isWaitingList: o.is_waiting_list,
    technicianName: o.assigned_to || '',
    technicianPhone: o.technician_phone || '',
    invoicePhoto: o.invoice_photo || null,
    invoiceAmount: o.invoice_amount,
    customerConfirmedAt: o.customer_confirmed_at || null,
    rating: o.rating,
    reviewText: o.review_text,
    complaintText: o.complaint_text,
    complaintStatus: o.complaint_status,
    createdAt: o.created_at,
    completedAt: o.completed_at,
  };
}

// ================= PUBLIC API =================

app.get('/api/catalog', async (req, res) => {
  try {
    const { rows } = await pool.query(
      "SELECT category, name, active FROM catalog_items ORDER BY category, sort_order, name"
    );
    res.json({
      devices: rows.filter(r => r.category === 'device' && r.active).map(r => r.name),
      serviceTypes: rows.filter(r => r.category === 'service_type' && r.active).map(r => r.name),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

app.get('/api/catalog/availability', async (req, res) => {
  try {
    const device = String(req.query.device || '').trim();
    if (!device) return res.status(400).json({ error: 'missing_device' });
    const result = await computeAvailability(device);
    res.json(result);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/orders', publicLimiter, async (req, res) => {
  try {
    const b = req.body || {};
    const name = String(b.name || '').trim().slice(0, 200);
    const phone = normPhone(b.phone);
    const device = String(b.device || '').trim().slice(0, 100);
    const service = String(b.service || '').trim().slice(0, 100);
    const description = String(b.description || '').trim().slice(0, 3000);
    const address = String(b.address || '').trim().slice(0, 500);
    const locationUrl = String(b.locationUrl || '').trim().slice(0, 500);
    const photoData = typeof b.photoData === 'string' ? b.photoData : null;

    if (!name || !phone || !device || !service || !description) {
      return res.status(400).json({ error: 'missing_fields' });
    }
    if (photoData && photoData.length > 6_000_000) {
      return res.status(400).json({ error: 'photo_too_large' });
    }

    const availability = await computeAvailability(device);
    const isWaitingList = !availability.available;
    const status = isWaitingList ? 'قائمة انتظار' : 'قيد المراجعة';
    const trackingToken = genTrackingToken();

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
        `INSERT INTO orders (customer_phone, name, phone, device, service, description, address, location_url, photo_data, status, is_waiting_list, waiting_reason, tracking_token, source)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'website')
         RETURNING id, created_at`,
        [phone, name, phone, device, service, description, address, locationUrl, photoData, status, isWaitingList, availability.reason || '', trackingToken]
      );
      await client.query('COMMIT');
      logHistory(orderResult.rows[0].id, null, status, 'system', req);
      res.json({
        ok: true,
        orderId: orderResult.rows[0].id,
        trackingToken,
        waitingList: isWaitingList,
        reason: availability.reason || '',
      });
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

app.get('/api/reviews/public', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT o.name, o.device, o.service, o.rating, o.review_text, o.created_at
      FROM orders o
      WHERE o.rating IS NOT NULL AND o.review_public = true
      ORDER BY o.completed_at DESC NULLS LAST, o.created_at DESC
      LIMIT 50
    `);
    const avgResult = await pool.query('SELECT AVG(rating)::numeric(10,2) AS avg, COUNT(*)::int AS c FROM orders WHERE rating IS NOT NULL');
    const reviews = rows.map(r => {
      const parts = String(r.name || '').trim().split(/\s+/);
      const displayName = parts.length > 1 ? `${parts[0]} ${parts[1][0]}.` : (parts[0] || 'عميل');
      return {
        name: displayName,
        device: r.device,
        service: r.service,
        rating: r.rating,
        reviewText: r.review_text,
        createdAt: r.created_at,
      };
    });
    res.json({
      reviews,
      average: avgResult.rows[0].avg ? Number(avgResult.rows[0].avg) : null,
      count: avgResult.rows[0].c,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

app.get('/api/track/:token', async (req, res) => {
  try {
    const token = String(req.params.token || '').trim().toUpperCase();
    const { rows } = await pool.query(
      `SELECT o.*, t.phone AS technician_phone
       FROM orders o LEFT JOIN technicians t ON t.id = o.technician_id
       WHERE o.tracking_token = $1`,
      [token]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'not_found' });
    const hist = await pool.query(
      'SELECT old_status, new_status, changed_by, changed_at FROM order_status_history WHERE order_id = $1 ORDER BY changed_at ASC',
      [rows[0].id]
    );
    const order = publicOrderView(rows[0]);
    order.history = hist.rows.map(h => ({
      oldStatus: h.old_status,
      newStatus: h.new_status,
      by: publicActorLabel(h.changed_by),
      changedAt: h.changed_at,
    }));
    res.json({ order });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/track/lookup', publicLimiter, async (req, res) => {
  try {
    const phone = normPhone((req.body || {}).phone);
    if (!phone) return res.status(400).json({ error: 'missing_phone' });
    const { rows } = await pool.query(
      `SELECT tracking_token, device, service, status, created_at FROM orders
       WHERE customer_phone = $1 ORDER BY created_at DESC LIMIT 20`,
      [phone]
    );
    res.json({
      orders: rows.map(r => ({
        trackingToken: r.tracking_token,
        device: r.device,
        service: r.service,
        status: r.status,
        createdAt: r.created_at,
      })),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/track/:token/rate', publicLimiter, async (req, res) => {
  try {
    const token = String(req.params.token || '').trim().toUpperCase();
    const rating = Number((req.body || {}).rating);
    const reviewText = String((req.body || {}).reviewText || '').trim().slice(0, 1000);
    const reviewPublic = (req.body || {}).reviewPublic !== false;
    if (!Number.isInteger(rating) || rating < 1 || rating > 5) {
      return res.status(400).json({ error: 'invalid_rating' });
    }
    const { rows } = await pool.query('SELECT id, status, rating FROM orders WHERE tracking_token = $1', [token]);
    if (rows.length === 0) return res.status(404).json({ error: 'not_found' });
    if (rows[0].status !== 'مكتمل') return res.status(400).json({ error: 'not_completed' });
    if (rows[0].rating !== null) return res.status(400).json({ error: 'already_rated' });
    await pool.query(
      'UPDATE orders SET rating = $1, review_text = $2, review_public = $3, updated_at = now() WHERE id = $4',
      [rating, reviewText, reviewPublic, rows[0].id]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/track/:token/complaint', publicLimiter, async (req, res) => {
  try {
    const token = String(req.params.token || '').trim().toUpperCase();
    const text = String((req.body || {}).text || '').trim().slice(0, 2000);
    if (!text) return res.status(400).json({ error: 'missing_text' });
    const { rows } = await pool.query('SELECT id FROM orders WHERE tracking_token = $1', [token]);
    if (rows.length === 0) return res.status(404).json({ error: 'not_found' });
    await pool.query(
      "UPDATE orders SET complaint_text = $1, complaint_status = 'جديدة', complaint_at = now(), updated_at = now() WHERE id = $2",
      [text, rows[0].id]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

// Customer confirms they actually received the service — an independent anti-tampering signal
// alongside the technician's invoice upload. Does not change the order's status.
app.post('/api/track/:token/confirm-completion', publicLimiter, async (req, res) => {
  try {
    const token = String(req.params.token || '').trim().toUpperCase();
    const { rows } = await pool.query('SELECT id, status, customer_confirmed_at FROM orders WHERE tracking_token = $1', [token]);
    if (rows.length === 0) return res.status(404).json({ error: 'not_found' });
    if (rows[0].status !== 'مكتمل') return res.status(400).json({ error: 'not_completed' });
    if (rows[0].customer_confirmed_at) return res.status(400).json({ error: 'already_confirmed' });
    await pool.query('UPDATE orders SET customer_confirmed_at = now(), updated_at = now() WHERE id = $1', [rows[0].id]);
    logHistory(rows[0].id, 'مكتمل', 'مكتمل', 'customer', req, { reason: 'تأكيد العميل باستلام الخدمة' });
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

// ================= STAFF AUTH =================
app.post('/api/staff/login', loginLimiter, async (req, res) => {
  try {
    const { password } = req.body || {};
    const ok = await verifyStaffPassword(String(password || ''));
    if (!ok) return res.status(401).json({ error: 'invalid_password' });
    res.cookie(STAFF_COOKIE, signToken({ role: 'staff' }), {
      httpOnly: true,
      sameSite: 'lax',
      secure: req.secure,
      maxAge: 12 * 60 * 60 * 1000,
    });
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});
app.post('/api/staff/logout', (req, res) => {
  res.clearCookie(STAFF_COOKIE);
  res.json({ ok: true });
});
app.get('/api/staff/me', (req, res) => {
  const payload = verifyJwt(req.cookies[STAFF_COOKIE]);
  res.json({ authenticated: !!(payload && payload.role === 'staff') });
});
// Change the staff-dashboard login password from inside the dashboard itself (Settings tab).
// Uses 400 (not 401) for a wrong current password / weak new password, so the dashboard's
// generic "401 -> bounce to /staff/login" handling doesn't kick the admin out mid-form.
app.post('/api/staff/change-password', requireStaff, loginLimiter, async (req, res) => {
  try {
    const b = req.body || {};
    const currentPassword = String(b.currentPassword || '');
    const newPassword = String(b.newPassword || '');
    if (newPassword.trim().length < 6) return res.status(400).json({ error: 'weak_password' });
    const currentOk = await verifyStaffPassword(currentPassword);
    if (!currentOk) return res.status(400).json({ error: 'wrong_current_password' });
    await setSetting('admin_password_hash', hashPassword(newPassword.trim()));
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

// Full self-service data export — lets staff download a complete backup of the platform's
// business data (orders, customers, technicians, catalog, and the full audit trail) as one
// JSON file, on demand, from inside the dashboard itself. Deliberately excludes anything
// secret (technician/staff password hashes, app_settings) — this file may end up stored
// somewhere less secure than the database itself, so it should never carry credentials.
app.get('/api/staff/backup', requireStaff, async (req, res) => {
  try {
    const [orders, customers, technicians, catalog, history] = await Promise.all([
      pool.query(`
        SELECT o.*, t.phone AS technician_phone
        FROM orders o LEFT JOIN technicians t ON t.id = o.technician_id
        ORDER BY o.id ASC
      `),
      pool.query('SELECT * FROM customers ORDER BY id ASC'),
      pool.query('SELECT id, name, phone, specialties, status, active, created_at FROM technicians ORDER BY id ASC'),
      pool.query('SELECT * FROM catalog_items ORDER BY category, sort_order, name'),
      pool.query('SELECT * FROM order_status_history ORDER BY order_id ASC, changed_at ASC'),
    ]);
    const stamp = new Date().toISOString().slice(0, 10);
    const backup = {
      generatedAt: new Date().toISOString(),
      platform: 'SEVENGATES',
      note: 'Business data export. Passwords and other secrets are intentionally not included.',
      orders: orders.rows,
      customers: customers.rows,
      technicians: technicians.rows,
      catalog: catalog.rows,
      orderStatusHistory: history.rows,
    };
    res.setHeader('Content-Disposition', `attachment; filename="sevengates-backup-${stamp}.json"`);
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.send(JSON.stringify(backup, null, 2));
  } catch (err) {
    console.error('Backup export failed:', err.message);
    res.status(500).json({ error: 'server_error' });
  }
});

// ================= STAFF API (protected) =================
app.get('/api/staff/orders', requireStaff, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT o.*, t.phone AS technician_phone
      FROM orders o LEFT JOIN technicians t ON t.id = o.technician_id
      ORDER BY o.created_at DESC LIMIT 1000
    `);
    const now = Date.now();
    const orders = rows.map(o => Object.assign({}, o, { sla_flag: computeSlaFlag(o, now) }));
    res.json({ orders });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

// Append-only audit trail for one order — who changed its status, when, and any flags raised.
app.get('/api/staff/orders/:id/history', requireStaff, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ error: 'invalid_id' });
    const { rows } = await pool.query(
      `SELECT old_status, new_status, changed_by, reason, flagged, flag_reason, ip_address, changed_at
       FROM order_status_history WHERE order_id = $1 ORDER BY changed_at ASC`,
      [id]
    );
    res.json({ history: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

app.patch('/api/staff/orders/:id', requireStaff, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ error: 'invalid_id' });
    const body = req.body || {};
    const sets = [];
    const values = [];
    let i = 1;

    let oldStatus = null;
    let willChangeStatus = false;
    if (Object.prototype.hasOwnProperty.call(body, 'status')) {
      const newStatus = String(body.status);
      if (!ORDER_STATUSES.includes(newStatus)) return res.status(400).json({ error: 'invalid_status' });
      // Marking an order complete is meant to happen only through the technician's invoice-upload
      // flow (which requires photo proof). A staff member can still do it directly for a genuine
      // edge case (e.g. a cash job handled outside the system), but must give a logged reason —
      // this closes the "quietly close the order with no proof of work" loophole.
      if (newStatus === 'مكتمل') {
        const reason = String(body.overrideReason || '').trim();
        if (!body.forceComplete || reason.length < 5) {
          return res.status(400).json({ error: 'complete_requires_override_reason' });
        }
      }
      const existing = await pool.query('SELECT status FROM orders WHERE id = $1', [id]);
      if (existing.rowCount === 0) return res.status(404).json({ error: 'not_found' });
      oldStatus = existing.rows[0].status;
      willChangeStatus = oldStatus !== newStatus;
      sets.push(`status = $${i++}`); values.push(newStatus);
    }
    if (Object.prototype.hasOwnProperty.call(body, 'notes')) {
      sets.push(`notes = $${i++}`); values.push(String(body.notes || '').slice(0, 5000));
    }
    if (Object.prototype.hasOwnProperty.call(body, 'reviewPublic')) {
      sets.push(`review_public = $${i++}`); values.push(!!body.reviewPublic);
    }
    if (Object.prototype.hasOwnProperty.call(body, 'complaintStatus')) {
      sets.push(`complaint_status = $${i++}`); values.push(body.complaintStatus);
    }

    let assignedTechForNotify = null;
    if (Object.prototype.hasOwnProperty.call(body, 'technicianId')) {
      if (body.technicianId === null) {
        sets.push(`technician_id = NULL`, `assigned_to = ''`, `assigned_at = NULL`);
      } else {
        const techId = Number(body.technicianId);
        const tech = await pool.query('SELECT id, name, phone FROM technicians WHERE id = $1', [techId]);
        if (tech.rowCount === 0) return res.status(400).json({ error: 'technician_not_found' });
        sets.push(`technician_id = $${i++}`); values.push(techId);
        sets.push(`assigned_to = $${i++}`); values.push(tech.rows[0].name);
        sets.push(`assigned_at = now()`);
        assignedTechForNotify = tech.rows[0];
        // moving out of the review/waiting stage once a technician is assigned
        if (!Object.prototype.hasOwnProperty.call(body, 'status')) {
          sets.push(`status = 'تمت الموافقة'`);
          sets.push(`is_waiting_list = false`);
          if (!willChangeStatus) {
            const existing = await pool.query('SELECT status FROM orders WHERE id = $1', [id]);
            if (existing.rowCount === 0) return res.status(404).json({ error: 'not_found' });
            oldStatus = existing.rows[0].status;
            willChangeStatus = oldStatus !== 'تمت الموافقة';
          }
        }
      }
    }

    if (sets.length === 0) return res.status(400).json({ error: 'no_fields' });
    sets.push('updated_at = now()');
    values.push(id);
    const sql = `UPDATE orders SET ${sets.join(', ')} WHERE id = $${i} RETURNING *`;
    const { rows } = await pool.query(sql, values);
    if (rows.length === 0) return res.status(404).json({ error: 'not_found' });
    if (willChangeStatus) {
      const isOverride = rows[0].status === 'مكتمل' && !!body.forceComplete;
      logHistory(id, oldStatus, rows[0].status, isOverride ? 'staff-override' : 'staff', req, {
        reason: isOverride ? String(body.overrideReason || '').trim() : '',
      });
    }
    if (assignedTechForNotify) {
      const order = rows[0];
      const baseUrl = `${req.protocol}://${req.get('host')}`;
      sendWhatsApp(
        order.phone,
        `مرحبًا ${order.name}، فريق SEVENGATES بيبلغك إن الفني *${assignedTechForNotify.name}* في الطريق إليك لتنفيذ خدمة (${order.device} - ${order.service}).\nرقم التواصل مع الفني: ${assignedTechForNotify.phone}\nتقدر تتابع حالة طلبك من هنا: ${baseUrl}/track/${order.tracking_token}`
      );
    }
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

app.get('/api/staff/technicians', requireStaff, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT tc.id, tc.name, tc.phone, tc.specialties, tc.status, tc.active, tc.created_at,
        COALESCE(oc.active_orders, 0)::int AS active_orders
      FROM technicians tc
      LEFT JOIN (
        SELECT technician_id, COUNT(*) AS active_orders FROM orders
        WHERE technician_id IS NOT NULL AND status IN ('تمت الموافقة', 'جاري التنفيذ')
        GROUP BY technician_id
      ) oc ON oc.technician_id = tc.id
      ORDER BY tc.created_at DESC
    `);
    res.json({ technicians: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/staff/technicians', requireStaff, async (req, res) => {
  try {
    const b = req.body || {};
    const name = String(b.name || '').trim();
    const phone = normPhone(b.phone);
    const password = String(b.password || '').trim();
    const specialties = Array.isArray(b.specialties) ? b.specialties.map(s => String(s).trim()).filter(Boolean) : [];
    if (!name || !phone || !password) return res.status(400).json({ error: 'missing_fields' });
    const { rows } = await pool.query(
      `INSERT INTO technicians (name, phone, password_hash, specialties, status, active)
       VALUES ($1,$2,$3,$4,'متاح',true) RETURNING id, name, phone, specialties, status, active, created_at`,
      [name, phone, hashPassword(password), specialties]
    );
    res.json({ technician: rows[0] });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'phone_exists' });
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

app.patch('/api/staff/technicians/:id', requireStaff, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ error: 'invalid_id' });
    const b = req.body || {};
    const sets = []; const values = []; let i = 1;
    if (b.name !== undefined) { sets.push(`name = $${i++}`); values.push(String(b.name).trim()); }
    if (b.specialties !== undefined) { sets.push(`specialties = $${i++}`); values.push(Array.isArray(b.specialties) ? b.specialties : []); }
    if (b.status !== undefined) { sets.push(`status = $${i++}`); values.push(String(b.status)); }
    if (b.active !== undefined) { sets.push(`active = $${i++}`); values.push(!!b.active); }
    if (b.password) { sets.push(`password_hash = $${i++}`); values.push(hashPassword(b.password)); }
    if (sets.length === 0) return res.status(400).json({ error: 'no_fields' });
    values.push(id);
    const { rows } = await pool.query(
      `UPDATE technicians SET ${sets.join(', ')} WHERE id = $${i} RETURNING id, name, phone, specialties, status, active, created_at`,
      values
    );
    if (rows.length === 0) return res.status(404).json({ error: 'not_found' });
    res.json({ technician: rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

app.get('/api/staff/catalog', requireStaff, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM catalog_items ORDER BY category, sort_order, name');
    res.json({ items: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/staff/catalog', requireStaff, async (req, res) => {
  try {
    const b = req.body || {};
    const category = String(b.category || '').trim();
    const name = String(b.name || '').trim();
    if (!['device', 'service_type'].includes(category) || !name) return res.status(400).json({ error: 'invalid_fields' });
    const { rows } = await pool.query(
      'INSERT INTO catalog_items (category, name, sort_order) VALUES ($1,$2,999) RETURNING *',
      [category, name]
    );
    res.json({ item: rows[0] });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'already_exists' });
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

app.patch('/api/staff/catalog/:id', requireStaff, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ error: 'invalid_id' });
    const b = req.body || {};
    const sets = []; const values = []; let i = 1;
    if (b.name !== undefined) { sets.push(`name = $${i++}`); values.push(String(b.name).trim()); }
    if (b.active !== undefined) { sets.push(`active = $${i++}`); values.push(!!b.active); }
    if (sets.length === 0) return res.status(400).json({ error: 'no_fields' });
    values.push(id);
    const { rows } = await pool.query(`UPDATE catalog_items SET ${sets.join(', ')} WHERE id = $${i} RETURNING *`, values);
    if (rows.length === 0) return res.status(404).json({ error: 'not_found' });
    res.json({ item: rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

// ================= TECHNICIAN AUTH + API =================
app.post('/api/tech/login', loginLimiter, async (req, res) => {
  try {
    const phone = normPhone((req.body || {}).phone);
    const password = String((req.body || {}).password || '');
    const { rows } = await pool.query('SELECT * FROM technicians WHERE phone = $1 AND active = true', [phone]);
    if (rows.length === 0 || !verifyPassword(password, rows[0].password_hash)) {
      return res.status(401).json({ error: 'invalid_credentials' });
    }
    res.cookie(TECH_COOKIE, signToken({ role: 'tech', id: rows[0].id }), {
      httpOnly: true,
      sameSite: 'lax',
      secure: req.secure,
      maxAge: 12 * 60 * 60 * 1000,
    });
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});
app.post('/api/tech/logout', (req, res) => {
  res.clearCookie(TECH_COOKIE);
  res.json({ ok: true });
});
app.get('/api/tech/me', async (req, res) => {
  const payload = verifyJwt(req.cookies[TECH_COOKIE]);
  if (!payload || payload.role !== 'tech') return res.json({ authenticated: false });
  const { rows } = await pool.query('SELECT id, name, phone, specialties, status FROM technicians WHERE id = $1 AND active = true', [payload.id]);
  if (rows.length === 0) return res.json({ authenticated: false });
  res.json({ authenticated: true, technician: rows[0] });
});

app.get('/api/tech/orders', requireTech, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT * FROM orders WHERE technician_id = $1 ORDER BY
        (status = 'مكتمل'), assigned_at DESC NULLS LAST, created_at DESC LIMIT 200`,
      [req.technician.id]
    );
    res.json({ orders: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

app.patch('/api/tech/orders/:id/start', requireTech, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const before = await pool.query('SELECT status FROM orders WHERE id = $1 AND technician_id = $2', [id, req.technician.id]);
    if (before.rowCount === 0) return res.status(404).json({ error: 'not_found' });
    const { rows } = await pool.query(
      "UPDATE orders SET status = 'جاري التنفيذ', updated_at = now() WHERE id = $1 AND technician_id = $2 RETURNING *",
      [id, req.technician.id]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'not_found' });
    logHistory(id, before.rows[0].status, 'جاري التنفيذ', `tech:${req.technician.id}:${req.technician.name}`, req);
    res.json({ order: rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/tech/orders/:id/complete', requireTech, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const invoicePhoto = typeof (req.body || {}).invoicePhoto === 'string' ? req.body.invoicePhoto : null;
    const invoiceAmount = Number((req.body || {}).invoiceAmount);
    if (!invoicePhoto) return res.status(400).json({ error: 'missing_invoice_photo' });
    if (!Number.isFinite(invoiceAmount) || invoiceAmount < 0) return res.status(400).json({ error: 'invalid_amount' });
    if (invoicePhoto.length > 6_000_000) return res.status(400).json({ error: 'photo_too_large' });
    const before = await pool.query('SELECT status, assigned_at FROM orders WHERE id = $1 AND technician_id = $2', [id, req.technician.id]);
    if (before.rowCount === 0) return res.status(404).json({ error: 'not_found' });
    const { rows } = await pool.query(
      `UPDATE orders SET status = 'مكتمل', invoice_photo = $1, invoice_amount = $2, completed_at = now(), updated_at = now()
       WHERE id = $3 AND technician_id = $4 RETURNING *`,
      [invoicePhoto, invoiceAmount, id, req.technician.id]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'not_found' });
    const order = rows[0];
    // Flag suspiciously fast completions (e.g. under 3 minutes from assignment) for staff review —
    // not blocked, since a genuinely quick job is possible, but surfaced as a signal.
    const assignedAt = before.rows[0].assigned_at ? new Date(before.rows[0].assigned_at).getTime() : null;
    const quickMs = assignedAt ? Date.now() - assignedAt : null;
    const flagged = quickMs !== null && quickMs < 3 * 60 * 1000;
    logHistory(id, before.rows[0].status, 'مكتمل', `tech:${req.technician.id}:${req.technician.name}`, req, {
      flagged,
      flagReason: flagged ? 'اكتمال سريع جدًا (أقل من 3 دقايق من التعيين)' : '',
    });
    const baseUrl = `${req.protocol}://${req.get('host')}`;
    sendWhatsApp(
      order.phone,
      `مرحبًا ${order.name}، تم إنجاز خدمة (${order.device} - ${order.service}) بنجاح ✅ شكرًا لثقتك في SEVENGATES.\nياريت تقيّم تجربتك وتكتب رأيك من هنا، ده بيهمنا جدًا: ${baseUrl}/track/${order.tracking_token}`
    );
    res.json({ order: rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

// ================= STATIC PAGES =================
app.use(express.static(path.join(__dirname, 'public')));

app.get('/staff', (req, res) => {
  const payload = verifyJwt(req.cookies[STAFF_COOKIE]);
  if (!payload || payload.role !== 'staff') return res.redirect('/staff/login');
  res.sendFile(path.join(__dirname, 'views', 'dashboard.html'));
});
app.get('/staff/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'login.html'));
});

app.get('/tech', (req, res) => {
  const payload = verifyJwt(req.cookies[TECH_COOKIE]);
  if (!payload || payload.role !== 'tech') return res.redirect('/tech/login');
  res.sendFile(path.join(__dirname, 'views', 'tech.html'));
});
app.get('/tech/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'tech-login.html'));
});

app.get('/track', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'track.html'));
});
app.get('/track/:token', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'track.html'));
});

app.get('/privacy', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'privacy.html'));
});
app.get('/terms', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'terms.html'));
});
app.get('/cookies', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'cookies.html'));
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
