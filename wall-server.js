/**
 * PARAMANT WALL — Backend v3.0
 * Geen wachtwoord · Geen trial · Email + terms → Stripe → webhook → key
 * Zero logging · Privacy by design · GDPR Art. 25
 */
'use strict';

const cluster = require('cluster');
const os      = require('os');
const http    = require('http');
const https   = require('https');
const crypto  = require('crypto');
const path    = require('path');

const PORT    = parseInt(process.env.PORT) || 4000;
const VERSION = '3.3.0';
const BASE    = process.env.WALL_BASE_URL || 'https://wall.paramant.app';
const IS_PROD = process.env.NODE_ENV === 'production';

// ── Cluster ──────────────────────────────────────────────────────
if (cluster.isPrimary) {
  const n = Math.min(os.cpus().length, 2);

  for (let i = 0; i < n; i++) cluster.fork();
  cluster.on('exit', function(w) {

    cluster.fork();
  });
  // Heartbeat log
  setInterval(function() {
    const ws = Object.values(cluster.workers);

  }, 5 * 60 * 1000);
  return;
}

const express  = require('express');
const Redis    = require('redis');
const { Pool } = require('pg');

const { BUILT_IN_TRACKERS, TEMPLATES, TRACKER_CATEGORIES, getTrackerAction } = require('./trackers');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY || '');
const app = express();
app.disable('x-powered-by');
app.disable('etag');

// Feed cleanup: max 100 events, max 10 min TTL
async function cleanFeedEvents(feedHash) {
  const key = 'feed:events:' + feedHash;
  try {
    const now = Date.now();
    const events = await redis.lRange(key, 0, -1).catch(() => []);
    const fresh = events
      .map(function(e) { try { return JSON.parse(e); } catch(x) { return null; } })
      .filter(function(e) { return e && (now - e.ts) < 600000; })
      .slice(-100);
    if (fresh.length !== events.length) {
      await redis.del(key);
      if (fresh.length > 0) {
        await redis.rPush(key, ...fresh.map(function(e) { return JSON.stringify(e); }));
        await redis.expire(key, 600);
      }
    }
  } catch(err) {}
}

async function deleteFeedData(feedHash) {
  if (!feedHash) return;
  await redis.del('feed:events:' + feedHash).catch(function() {});
  await redis.del('feed:stats:' + feedHash).catch(function() {});
}


// Pending accounts cleanup: verwijder records ouder dan 2 uur die niet betaald zijn
async function cleanPendingAccounts() {
  try {
    const r = await pg.query(
      "DELETE FROM pending_accounts WHERE created_at < NOW() - INTERVAL '2 hours' AND (payment_processed IS NULL OR payment_processed=false) RETURNING email"
    );
    if (r.rows.length > 0) {
      // Cleanup verlopen view_tokens (A07 — geen accumulation)
      await pg.query("DELETE FROM view_tokens WHERE expires_at < NOW() - INTERVAL '1 hour'").catch(function(){});
      // Cleanup gebruikte magic_links
      await pg.query("DELETE FROM magic_links WHERE used=true OR expires_at < NOW() - INTERVAL '1 hour'").catch(function(){});
    }
  } catch(e) {
    console.error('[WALL:ERR] pending_cleanup error:', e.code || e.message.slice(0,40));
  }
}
// Run elke 15 minuten
setInterval(cleanPendingAccounts, 15 * 60 * 1000);
// Ook direct bij startup
setTimeout(cleanPendingAccounts, 10000);

// Cleanup job elke 5 minuten
setInterval(async function() {
  try {
    const hashes = await pg.query('SELECT feed_hash FROM projects').catch(function() { return {rows:[]}; });
    for (const row of hashes.rows) {
      await cleanFeedEvents(row.feed_hash);
    }
  } catch(err) {}
}, 300000);

app.use(express.json({ limit: '32kb' }));

// ── Input validatie helpers ─────────────────────────────────────
function sanitizeEmail(email) {
  if (!email || typeof email !== 'string') return null;
  var e = email.toLowerCase().trim().slice(0, 254);
  if (!/^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/.test(e)) return null;
  return e;
}

function sanitizeDomain(domain) {
  if (!domain || typeof domain !== 'string') return [];
  return domain.split(',')
    .map(function(d) { return d.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, ''); })
    .filter(function(d) { return d.length > 0 && d.length < 255 && /^[a-z0-9][a-z0-9\-\.]*[a-z0-9]$/.test(d); })
    .slice(0, 150);
}

function sanitizePlan(plan) {
  var valid = ['starter','pro','business','test'];
  return valid.indexOf(plan) >= 0 ? plan : 'starter';
}

function sanitizeTemplate(tpl) {
  var valid = ['ultra-streng','basis-analytics','marketing-light','custom'];
  return valid.indexOf(tpl) >= 0 ? tpl : 'ultra-streng';
}

function sanitizeString(str, maxLen) {
  if (!str || typeof str !== 'string') return '';
  return str.trim().slice(0, maxLen || 500).replace(/<[^>]*>/g, '');
}

// Request size limit middleware (5MB max)
app.use(function(req, res, next) {
  var size = parseInt(req.headers['content-length'] || 0);
  if (size > 5 * 1024 * 1024) {
    return res.status(413).json({ error: 'payload_too_large' });
  }
  next();
});

// Security middleware: verwijder server info
app.use(function(req, res, next) {
  res.removeHeader('X-Powered-By');
  res.removeHeader('Server');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

// ── Security headers ─────────────────────────────────────────────
app.use(function(req, res, next) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'");
  res.setHeader('Permissions-Policy', 'geolocation=(), camera=(), microphone=()');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cache-Control', 'no-store');
  next();
});

// ── CORS ─────────────────────────────────────────────────────────
app.use(function(req, res, next) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-API-Key, X-Wall-Key');
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
});

// ── Veilige IP extractie — vertrouw alleen X-Real-IP van Nginx ──
// X-Forwarded-For kan door clients gespoofed worden — nooit direct vertrouwen
function getClientIP(req) {
  // X-Real-IP wordt door Nginx gezet — niet door de client aanpasbaar
  return req.headers['x-real-ip'] || req.socket.remoteAddress || '0.0.0.0';
}

// Jitter helper — voorkomt timing attacks op recover/gdpr endpoints
function randomJitter(minMs, maxMs) {
  return new Promise(function(resolve) {
    setTimeout(resolve, minMs + Math.random() * (maxMs - minMs));
  });
}

// ── Redis + PostgreSQL ────────────────────────────────────────────
const redis = Redis.createClient({
  url: process.env.REDIS_URL || 'redis://localhost:6379',
  socket: {
    reconnectStrategy: function(retries) {
      if (retries > 20) {
        console.error('[WALL:ERR] Redis: max retries bereikt — offline mode');
        return new Error('Redis max retries');
      }
      return Math.min(retries * 200, 5000); // max 5 sec tussen pogingen
    },
    connectTimeout: 3000,
  }
});

redis.on('error', function(e) {
  if (!e.message.includes('ECONNREFUSED')) return; // stil voor bekende fouten
  console.error('[WALL:ERR] Redis error:', e.message);
});
redis.on('reconnecting', function() { console.warn('[WALL] Redis: herverbinden...'); });
redis.on('ready', function() { console.log('[WALL] Redis: verbonden'); });

redis.connect().catch(function(e) { console.error('[WALL:ERR] Redis connect:', e.message); });

// Helper: safe redis get met fallback
async function redisGet(key) {
  try { return await redis.get(key); } catch(e) { return null; }
}
async function redisSet(key, val, ttl) {
  try { return ttl ? await redis.setEx(key, ttl, val) : await redis.set(key, val); } catch(e) { return null; }
}
async function redisIncr(key) {
  try { return await redis.incr(key); } catch(e) { return 1; } // fail-open: geen rate limit
}

const pg = new Pool({
  connectionString: process.env.DATABASE_URL,
  max:              20,        // Max 20 gelijktijdige verbindingen
  min:              2,         // Altijd 2 warm
  idleTimeoutMillis: 30000,    // 30s idle timeout
  connectionTimeoutMillis: 5000, // 5s connect timeout
  statement_timeout: 10000,    // 10s query timeout
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('sslmode=require')
    ? { rejectUnauthorized: false }
    : false,
});
// Pool error handler (voorkomt crash bij DB disconnect)
pg.on('error', function(err) {
  console.error('[WALL:ERR] PG pool error:', err.code || err.message.slice(0,40));
});

// ── Session token ─────────────────────────────────────────────────
const SESSION_SECRET = process.env.SESSION_SECRET;
if (!SESSION_SECRET) {
  console.error('[WALL:ERR] FATAL: SESSION_SECRET not set');
}

function createToken(userId) {
  const payload = userId + ':' + Math.floor(Date.now() / 1000);
  if (!SESSION_SECRET) throw new Error('SESSION_SECRET not configured');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('hex');
  return Buffer.from(payload + ':' + sig).toString('base64url');
}

function verifyToken(token) {
  try {
    const decoded = Buffer.from(token, 'base64url').toString();
    const parts   = decoded.split(':');
    if (parts.length !== 3) return null;
    const [userId, ts, sig] = parts;
    const payload  = userId + ':' + ts;
    if (!SESSION_SECRET) return null;
    const expected = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('hex');
    if (!crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(sig))) return null;
    if (Date.now() / 1000 - parseInt(ts) > 86400 * 30) return null;
    return userId;
  } catch { return null; }
}

// ── Helpers ───────────────────────────────────────────────────────
function sha256(str) {
  return crypto.createHash('sha256').update(String(str), 'utf8').digest('hex');
}
function dailySalt() {
  const d = new Date();
  return 'wall-' + d.getUTCFullYear() + '-' + d.getUTCMonth() + '-' + d.getUTCDate();
}
function anonymizeIP(ip) {
  if (!ip) return 'unknown';
  return sha256(ip.trim() + dailySalt()).slice(0, 16);
}
function anonymizeUA(ua) {
  if (!ua) return 'Other';
  if (/Chrome/i.test(ua))  return 'Chrome';
  if (/Firefox/i.test(ua)) return 'Firefox';
  if (/Safari/i.test(ua))  return 'Safari';
  if (/Edge/i.test(ua))    return 'Edge';
  return 'Other';
}

// ── Input validation ──────────────────────────────────────────────
const EMAIL_RE = /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/;
function validateEmail(e) {
  if (typeof e !== 'string') return null;
  const clean = e.trim().toLowerCase().slice(0, 254);
  return EMAIL_RE.test(clean) ? clean : null;
}

// ── Rate limiting ─────────────────────────────────────────────────
async function rateLimit(key, max, windowSec) {
  try {
    const rk = 'rl:' + key + ':' + Math.floor(Date.now() / (windowSec * 1000));
    const n  = await redis.incr(rk);
    if (n === 1) await redis.expire(rk, windowSec + 10);
    return n <= max;
  } catch { return true; }
}

// ── DB: pending_accounts table aanmaken als die niet bestaat ──────
async function ensureTables() {
  try {
    await pg.query(`
      CREATE TABLE IF NOT EXISTS pending_accounts (
        id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        email         TEXT NOT NULL,
        plan          TEXT NOT NULL DEFAULT 'starter',
        stripe_session TEXT,
        view_token    TEXT,
        expires_at    TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '2 hours',
        completed_at  TIMESTAMPTZ,
        created_at    TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_pending_email ON pending_accounts(email);
      CREATE INDEX IF NOT EXISTS idx_pending_session ON pending_accounts(stripe_session);
      CREATE TABLE IF NOT EXISTS view_tokens (
        token         TEXT PRIMARY KEY,
        user_id       UUID NOT NULL,
        expires_at    TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '1 hour',
        created_at    TIMESTAMPTZ DEFAULT NOW()
      );
    `);
  } catch(e) {
    console.error('[WALL:ERR] ensureTables:', e.message);
  }
}
ensureTables();

// ── Core registratie functie (ook gebruikt door webhook) ──────────
async function activateAccount({ email, plan, domain, stripeCustomerId, stripeSubId, wasReplaced }) {
  // IDEMPOTENCY: voorkom dubbele activatie
  try {
    const existing = await pg.query(
      'SELECT id, enabled FROM customers WHERE user_id IN (SELECT id FROM users WHERE email=$1) AND enabled=true LIMIT 1',
      [email]
    );
    if (existing.rows.length > 0) {
          await logSecurityEvent('key_activated', {reason:'duplicate_skipped'});
      return { ok: true, skipped: true };
    }
    const pend = await pg.query(
      'SELECT payment_processed FROM pending_accounts WHERE email=$1 LIMIT 1', [email]
    );
    if (pend.rows.length > 0 && pend.rows[0].payment_processed) {
            return { ok: true, skipped: true };
    }
    await pg.query(
      'UPDATE pending_accounts SET payment_processed=true, processed_at=NOW() WHERE email=$1', [email]
    ).catch(function(){});
  } catch(e) {}

  const client = await pg.connect();
  try {
    await client.query('BEGIN');

    // Invalideer oude accounts van dit e-mail
    const oldUsers = await client.query(
      'SELECT id FROM users WHERE email = $1 AND deleted_at IS NULL',
      [email]
    );
    for (const row of oldUsers.rows) {
      await client.query('UPDATE customers SET enabled = false WHERE user_id = $1', [row.id]);
      await client.query('UPDATE users SET deleted_at = NOW() WHERE id = $1', [row.id]);
    }

    const userId     = crypto.randomUUID();
    const customerId = crypto.randomUUID();
    const projectId  = crypto.randomUUID();
    const apiKey     = 'wk_' + crypto.randomBytes(24).toString('hex');
    const hmacSecret = crypto.randomBytes(32).toString('hex');
    const feedHash   = crypto.randomBytes(8).toString('hex');
    const keyHash    = sha256(apiKey);
    const snippet    = `<script src="${BASE}/snippet.js?k=${apiKey}" async></script>`;

    // Dummy password hash (geen wachtwoord nodig)
    const pwHash = 'magic:' + crypto.randomBytes(32).toString('hex');

    // 1. User
    await client.query(
      'INSERT INTO users (id, email, password_hash, created_at) VALUES ($1, $2, $3, NOW())',
      [userId, email, pwHash]
    );

    // 2. Customer
    await client.query(
      'INSERT INTO customers (id, user_id, api_key, plan, enabled, config, key_hash, key_prefix, email) VALUES ($1, $2, $3, $4, true, $5, $6, $7, $8)',
      [customerId, userId, apiKey, plan, JSON.stringify({ hmac_secret: hmacSecret }), keyHash, apiKey.slice(0, 12), email]
    );

    // 3. Project
    await client.query(
      'INSERT INTO projects (id, customer_id_ref, name, feed_hash, created_at, allowed_domains) VALUES ($1, $2, $3, $4, NOW(), $5)',
      [projectId, customerId, 'Mijn eerste site', feedHash,
       domain ? JSON.stringify([domain.replace(/^https?:\/\//, '').replace(/\/.*/, '').replace(/^www\./, '')]) : '{}']
    );

    // 4. Wall config
    await client.query(
      'INSERT INTO wall_configs (id, project_id, template, config_json, created_at) VALUES (gen_random_uuid(), $1, $2, $3, NOW())',
      [projectId, 'ultra-streng', JSON.stringify({
        anonymize: { ip: true, userAgent: true, clientId: true },
        strip_always: ['cookie', 'user_id', 'email'],
        logging: 'none',
      })]
    );

    // 5. Subscription
    const subStatus = plan === 'test' ? 'trialing' : 'active';
    const periodEnd = plan === 'test' ? "NOW() + INTERVAL '10 minutes'" : 'NULL';
    await client.query(
      `INSERT INTO subscriptions (id, customer_id_ref, plan, status, stripe_sub_id, period_start, period_end)
       VALUES (gen_random_uuid(), $1, $2, $3, $4, NOW(), ${periodEnd})`,
      [customerId, plan, subStatus, stripeSubId || null]
    );
    // Test key: plan automatisch deactiveren na 1 uur
    if (plan === 'test') {
      setTimeout(async function() {
        try {
          await pg.query('UPDATE customers SET enabled = false WHERE id = $1', [customerId]);
        } catch(_) {}
      }, 10 * 60 * 1000);
    }

    // 6. View token voor success pagina (eenmalig)
    const viewToken = crypto.randomBytes(24).toString('hex');
    await client.query(
      'INSERT INTO view_tokens (token, user_id, expires_at) VALUES ($1, $2, NOW() + INTERVAL \'1 hour\')',
      [viewToken, userId]
    );

    await client.query('COMMIT');

    return { userId, apiKey, feedHash, snippet, viewToken, wasReplaced };
  } catch(e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}

// ══════════════════════════════════════════════════════════════════
// STAP 1: REGISTER — email + terms → pending + Stripe checkout
// ══════════════════════════════════════════════════════════════════
app.post('/api/auth/register', async function(req, res) {
  const body     = req.body || {};
  const email    = sanitizeEmail(body.email);
  const plan     = sanitizePlan(body.plan);
  const domains  = sanitizeDomain(body.domain || '');
  const domain   = domains.join(',');
  const template = sanitizeTemplate(body.template);

  if (!email) return res.status(400).json({ error: 'invalid_email' });

  // Validatie
  if (!email || email.indexOf('@') < 1 || email.length > 200) {
    return res.status(400).json({ error: 'invalid_email' });
  }
  if (!body.acceptTerms) {
    return res.status(400).json({ error: 'terms_required' });
  }

  // IP rate limit: max 3/uur
  const ip     = getClientIP(req);
  const ipHash = sha256(ip).slice(0, 20);
  const ipKey  = 'reg_rl:' + ipHash;
  const ipCnt  = parseInt(await redis.get(ipKey).catch(function(){ return 0; })) || 0;
  if (ipCnt >= 3) return res.status(429).json({ error: 'rate_limit', retry_after: 3600 });
  await redis.setEx(ipKey, 3600, String(ipCnt + 1)).catch(function(){});

  // Plan → Stripe price
  const PRICES = {
    starter:  process.env.STRIPE_PRICE_STARTER,
    pro:      process.env.STRIPE_PRICE_PRO,
    business: process.env.STRIPE_PRICE_BUSINESS,
    test:     process.env.STRIPE_PRICE_TEST,
  };
  const priceId = PRICES[plan];
  if (!priceId) return res.status(400).json({ error: 'invalid_plan' });

  // GEEN DB INSERT — alles gaat via Stripe metadata
  // User wordt pas aangemaakt NA succesvolle betaling in de webhook
  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card', 'ideal', 'sepa_debit'],
      mode: 'subscription',
      line_items: [{ price: priceId, quantity: 1 }],
      customer_email: email,
      success_url: (process.env.BASE_URL || 'https://wall.paramant.app') + '/success?session_id={CHECKOUT_SESSION_ID}',
      cancel_url:  (process.env.BASE_URL || 'https://wall.paramant.app') + '/cancel',
      metadata: {
        email:           email,
        plan:            plan,
        domain:          domain.slice(0, 500),
        template:        template,
        tracker_config:  JSON.stringify(body.trackerConfig  || {}).slice(0, 490),
        custom_trackers: JSON.stringify(body.customTrackers || []).slice(0, 490),
      },
      subscription_data: {
        metadata: { email, plan, domain: domain.slice(0, 500), template }
      },
      allow_promotion_codes: true,
    });

        return res.json({ ok: true, checkout_url: session.url });
  } catch(e) {
    console.error('[WALL:ERR] Stripe session error:', e.message.slice(0, 80));
    return res.status(500).json({ error: 'payment_error' });
  }
});


app.post('/api/stripe/webhook', express.raw({ type: 'application/json' }), async function(req, res) {
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch(e) {
    console.error('[WALL:ERR] Webhook sig invalid:', e.message.slice(0, 60));
    return res.status(400).json({ error: 'invalid_signature' });
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const meta    = session.metadata || {};
    const email   = meta.email || session.customer_email || '';
    const plan    = meta.plan  || 'starter';
    const domain  = meta.domain || '';
    const template = meta.template || 'ultra-streng';

    if (!email) return res.json({ ok: true, skipped: 'no_email' });

    // Idempotency: check of user al bestaat
    const existing = await pg.query(
      'SELECT c.id, c.api_key FROM customers c JOIN users u ON u.id=c.user_id WHERE u.email=$1 AND c.enabled=true LIMIT 1',
      [email]
    );
    if (existing.rows.length > 0) {
            return res.json({ ok: true, skipped: 'already_active' });
    }

    try {
      await activateAccount({
        email, plan, domain,
        stripeCustomerId: session.customer,
        stripeSubId:      session.subscription,
        template,
        trackerConfig:    meta.tracker_config,
        customTrackers:   meta.custom_trackers,
      });
      await logSecurityEvent('key_activated', { plan, ipHash: '' }).catch(function(){});
          } catch(e) {
      console.error('[WALL:ERR] Webhook activateAccount error:', e.message.slice(0, 80));
    }
  }

  if (event.type === 'customer.subscription.deleted') {
    const sub   = event.data.object;
    const email = sub.metadata && sub.metadata.email;
    if (email) {
      await pg.query(
        'UPDATE customers SET enabled=false WHERE user_id IN (SELECT id FROM users WHERE email=$1)', [email]
      ).catch(function(){});
      const feedRows = await pg.query(
        'SELECT p.feed_hash FROM projects p JOIN customers c ON c.id=p.customer_id_ref JOIN users u ON u.id=c.user_id WHERE u.email=$1',
        [email]
      ).catch(function(){ return { rows: [] }; });
      for (const fr of feedRows.rows) { await deleteFeedData(fr.feed_hash); }
          }
  }

  return res.json({ ok: true });
});


app.get('/success', async function(req, res) {
  // Via Stripe redirect: ?s=session_id
  const sessionId  = req.query.s;
  // Via email link: ?view=token
  const viewToken  = req.query.view;

  let userData = null;

  if (viewToken) {
    try {
      const vt = await pg.query(
        `SELECT vt.user_id FROM view_tokens vt
         WHERE vt.token = $1 AND vt.expires_at > NOW() LIMIT 1`,
        [viewToken]
      );
      if (vt.rows.length) {
        userData = await getUserData(vt.rows[0].user_id);
      }
    } catch(_) {}
  }

  if (!userData && sessionId) {
    try {
      const session = await stripe.checkout.sessions.retrieve(stripeSessionId);
      if (session.customer_email || (session.metadata && session.metadata.email)) {
        const email = session.customer_email || session.metadata.email;
        // Wacht even op webhook
        await new Promise(r => setTimeout(r, 1500));
        const ur = await pg.query(
          'SELECT id FROM users WHERE email = $1 AND deleted_at IS NULL ORDER BY created_at DESC LIMIT 1',
          [email]
        );
        if (ur.rows.length) {
          userData = await getUserData(ur.rows[0].id);
        }
      }
    } catch(_) {}
  }

  res.sendFile(path.join(__dirname, 'public', 'success.html'));
});

// API voor success pagina data
app.get('/api/success-data', async function(req, res) {
  // Stripe sessie verificatie als session_id aanwezig
  const stripeSessionId = req.query.session_id;
  if (stripeSessionId && stripe) {
    try {
      const session = await stripe.checkout.sessions.retrieve(stripeSessionId);
      if (session.payment_status !== 'paid' && session.status !== 'complete') {
        return res.status(402).json({ error: 'payment_not_completed', status: session.payment_status });
      }
    } catch(e) {
      console.error('[WALL:ERR] Stripe session verify error:', e.message.slice(0,50));
      // Niet blokkeren bij Stripe API fout - ga door met DB check
    }
  }

  const ip = getClientIP(req);
  if (!await rateLimit('succ:' + anonymizeIP(ip), 30, 60)) {
    logSecurityEvent('rate_limit_hit', {}).catch(function(){});
  return res.status(429).json({ error: 'rate_limit' });
  }
  const sessionId = req.query.s;
  const viewToken = req.query.view;

  if (viewToken) {
    try {
      const vt = await pg.query(
        'SELECT user_id FROM view_tokens WHERE token = $1 AND expires_at > NOW() LIMIT 1',
        [viewToken]
      );
      if (vt.rows.length) {
        const data = await getUserData(vt.rows[0].user_id);
        if (data) return res.json({ ok: true, ...data });
      }
    } catch(_) {}
    return res.status(404).json({ error: 'not_found' });
  }

  if (sessionId) {
    try {
      const session = await stripe.checkout.sessions.retrieve(stripeSessionId);
      
      // Check of betaling gelukt is
      if (session.status === 'expired') {
        return res.status(410).json({ error: 'session_expired', msg: 'Deze betalingssessie is verlopen. Probeer opnieuw.' });
      }
      if (session.payment_status === 'unpaid' && session.status !== 'open') {
        return res.status(402).json({ error: 'payment_failed', msg: 'Betaling niet geslaagd. Probeer opnieuw.' });
      }

      const email = session.customer_email || (session.metadata && session.metadata.email);
      if (email) {
        // Poll max 20s op webhook (10 pogingen x 2s)
        for (let i = 0; i < 10; i++) {
          await new Promise(r => setTimeout(r, 2000));
          const ur = await pg.query(
            'SELECT id FROM users WHERE email = $1 AND deleted_at IS NULL ORDER BY created_at DESC LIMIT 1',
            [email]
          );
          if (ur.rows.length) {
            const data = await getUserData(ur.rows[0].id);
            if (data) return res.json({ ok: true, ...data });
          }
        }
        // Nog niet actief - stuur pending response
        return res.status(202).json({ 
          error: 'pending', 
          msg: 'Account wordt nog geactiveerd. Je ontvangt een e-mail zodra het klaar is.',
          email: email
        });
      }
    } catch(e) {
      console.error('[WALL:ERR] success-data error:', e.message);
    }
    return res.status(404).json({ error: 'not_found', msg: 'Account nog niet actief. Ververs de pagina.' });
  }

  return res.status(400).json({ error: 'missing_params' });
});

async function getUserData(userId) {
  try {
    const r = await pg.query(
      `SELECT u.email, c.api_key, c.plan, p.feed_hash, s.status as sub_status
       FROM users u
       JOIN customers c ON c.user_id = u.id
       JOIN projects p  ON p.customer_id_ref = c.id
       LEFT JOIN subscriptions s ON s.customer_id_ref = c.id
       WHERE u.id = $1 AND c.enabled = true
       ORDER BY c.created_at DESC LIMIT 1`,
      [userId]
    );
    if (!r.rows.length) return null;
    const d = r.rows[0];
    return {
      email:    d.email,
      api_key:  d.api_key,
      plan:     d.plan,
      feed_url: BASE + '/feed/' + d.feed_hash,
      feed_hash: d.feed_hash,
      snippet:  `<script src="${BASE}/snippet.js?k=${d.api_key}" async></script>`,
      sub_status: d.sub_status,
    };
  } catch { return null; }
}

// ══════════════════════════════════════════════════════════════════
// LOGIN via magic link (geen wachtwoord)
// ══════════════════════════════════════════════════════════════════
app.post('/api/auth/login', async function(req, res) {
  const email = validateEmail(req.body && req.body.email);
  if (!email) return res.status(400).json({ error: 'invalid_email' });

  const ip = getClientIP(req);
  if (!await rateLimit('login:' + anonymizeIP(ip), 5, 900)) {
    logSecurityEvent('rate_limit_hit', {}).catch(function(){});
    return res.status(429).json({ error: 'rate_limit' });
  }

  const r = await pg.query(
    'SELECT id FROM users WHERE email = $1 AND deleted_at IS NULL ORDER BY created_at DESC LIMIT 1',
    [email]
  ).catch(() => ({ rows: [] }));

  if (!r.rows.length) {
    // Zeg altijd OK om email enumeration te voorkomen
    return res.json({ ok: true, msg: 'Als dit e-mail bekend is, ontvang je een inloglink.' });
  }

  const viewToken = crypto.randomBytes(24).toString('hex');
  await pg.query(
    'INSERT INTO view_tokens (token, user_id, expires_at) VALUES ($1, $2, NOW() + INTERVAL \'1 hour\')',
    [viewToken, r.rows[0].id]
  ).catch(() => {});

  await sendMagicLinkEmail(email, BASE + '/success?view=' + viewToken);
  return res.json({ ok: true, msg: 'Inloglink verstuurd naar je e-mail.' });
});

// ══════════════════════════════════════════════════════════════════
// PUBLIC FEED API
// ══════════════════════════════════════════════════════════════════
app.get('/api/feed/:hash', async function(req, res) {
  const { hash } = req.params;
  if (!hash || !/^[a-f0-9]{16}$/.test(hash)) return res.status(400).json({ error: 'invalid_hash' });
  try {
    const proj = await pg.query(
      'SELECT p.customer_id_ref, p.name FROM projects p WHERE p.feed_hash=$1 LIMIT 1', [hash]
    );
    if (!proj.rows.length) return res.status(404).json({ error: 'not_found' });
    const cid   = proj.rows[0].customer_id_ref;
    const month = new Date().toISOString().slice(0, 7);

    const totals = await pg.query(
      'SELECT requests, blocked, stripped, allowed FROM usage_monthly WHERE customer_id=$1 AND month=$2',
      [cid, month]
    );
    const d = totals.rows[0] || { requests:0, blocked:0, stripped:0, allowed:0 };
    const total = parseInt(d.requests) || 0;
    const pct   = function(n){ return total > 0 ? Math.round((parseInt(n)||0)/total*100) : 0; };

    // Live events + breakdown per tracker
    const raw = await redis.lRange('feed:events:' + hash, 0, 99).catch(function(){ return []; });
    const events = raw.map(function(e){ try{ return JSON.parse(e); }catch(x){ return null; } })
                      .filter(Boolean).sort(function(a,b){ return b.ts - a.ts; });

    const breakdown = {};
    events.forEach(function(ev) {
      var tk = ev.tracker || 'unknown';
      if (!breakdown[tk]) breakdown[tk] = { blocked:0, stripped:0, allowed:0 };
      var a = ev.action || 'allowed';
      if (a === 'block'   || a === 'blocked')  breakdown[tk].blocked++;
      else if (a === 'strip' || a === 'stripped') breakdown[tk].stripped++;
      else                                        breakdown[tk].allowed++;
    });

    return res.json({
      ok: true,
      feed: {
        hash, month,
        name:    proj.rows[0].name || 'PARAMANT WALL Feed',
        totals: {
          requests: total,
          blocked:  parseInt(d.blocked)  || 0,
          stripped: parseInt(d.stripped) || 0,
          allowed:  parseInt(d.allowed)  || 0,
          pct_blocked:  pct(d.blocked),
          pct_stripped: pct(d.stripped),
          pct_allowed:  pct(d.allowed),
        },
        breakdown: breakdown,
        live_events: events.slice(0, 20),
        ts: new Date().toISOString(),
      }
    });
  } catch(e) {
    console.error('[WALL:ERR] feed error:', e.code || e.message.slice(0,40));
    return res.status(500).json({ error: 'feed_error' });
  }
});

app.get('/feed/:hash', function(req, res) {
  res.sendFile(path.join(__dirname, 'public', 'feed.html'));
});

// ══════════════════════════════════════════════════════════════════
// PROXY ENDPOINTS (GA4, Meta)
// ══════════════════════════════════════════════════════════════════
async function getCustomer(apiKey) {
  if (!apiKey || !/^wk_[a-f0-9]{48}$/.test(apiKey)) return null;
  const cacheKey = 'wk:' + sha256(apiKey);
  const cached = await redisGet(cacheKey);
  if (cached) { try { return JSON.parse(cached); } catch { return null; } }
  try {
    const r = await pg.query(
      `SELECT c.id, c.plan, c.enabled, c.config, p.feed_hash, p.allowed_domains
       FROM customers c
       JOIN projects p ON p.customer_id_ref = c.id
       WHERE c.api_key = $1 AND c.enabled = true LIMIT 1`,
      [apiKey]
    );
    if (!r.rows.length) return null;
    await redisSet(cacheKey, JSON.stringify(r.rows[0]), 60);
    return r.rows[0];
  } catch { return null; }
}


async function revokeKey(apiKey, reason) {
  if (!apiKey) return;
  const keyHash = sha256(apiKey).slice(0,16);
  const cacheKey = 'wk:' + sha256(apiKey);
  // Redis: markeer als revoked (24 uur cache)
  await redis.setEx('revoked:' + keyHash, 86400, reason || 'revoked').catch(function(){});
  // Verwijder customer cache
  await redis.del(cacheKey).catch(function(){});
  // DB: disable customer
  await pg.query('UPDATE customers SET enabled=false WHERE api_key=$1', [apiKey]).catch(function(){});
  console.log('[WALL] Key revoked:', keyHash, 'reden:', reason || 'unknown');
  // Was jij dit? email
  pg.query('SELECT u.email FROM users u JOIN customers c ON c.user_id=u.id WHERE c.api_key=$1 LIMIT 1', [apiKey])
    .then(function(r){ if(r.rows.length) sendKeyInvalidationEmail(r.rows[0].email, reason||'key_revoked'); })
    .catch(function(){});
  await logSecurityEvent('key_revoked', { keyHint: keyHash, reason: reason||'unknown' }).catch(function(){});
  await logSecurityEvent('key_revoked', {keyHint: keyHash, reason: reason||'unknown'});
  // Stuur "Was jij dit?" email
  try {
    const userRow = await pg.query(
      'SELECT u.email FROM users u JOIN customers c ON c.user_id=u.id WHERE c.api_key=$1 LIMIT 1',
      [apiKey]
    );
    if (userRow.rows.length > 0) {
      await sendKeyInvalidationEmail(userRow.rows[0].email, reason || 'key_revoked', null);
    }
  } catch(e) {}
}

// ── Email helpers ─────────────────────────────────────────────────────────

// ── Security event logger (geen PII) ─────────────────────────────────────
async function logSecurityEvent(eventType, meta) {
// ── API Key rotatie ──────────────────────────────────────────────
app.post('/api/auth/rotate-key', async function(req, res) {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.replace('Bearer ', '').trim();
  if (!token) return res.status(401).json({ error: 'unauthorized' });

  try {
    // Valideer token → zoek user
    const tokenHash = sha256(token);
    const vtRow = await pg.query(
      'SELECT user_id FROM view_tokens WHERE token_hash=$1 AND expires_at > NOW() LIMIT 1',
      [tokenHash]
    );
    if (!vtRow.rows.length) return res.status(401).json({ error: 'invalid_token' });
    const userId = vtRow.rows[0].user_id;

    // Haal huidige API key op
    const custRow = await pg.query(
      'SELECT id, api_key FROM customers WHERE user_id=$1 AND enabled=true LIMIT 1',
      [userId]
    );
    if (!custRow.rows.length) return res.status(404).json({ error: 'customer_not_found' });

    const oldKey  = custRow.rows[0].api_key;
    const custId  = custRow.rows[0].id;

    // Genereer nieuwe key
    const newKey  = 'wk_' + require('crypto').randomBytes(24).toString('hex');

    // Sla nieuwe key op + revoke oude in één transactie
    const client = await pg.connect();
    try {
      await client.query('BEGIN');
      await client.query(
        'UPDATE customers SET api_key=$1 WHERE id=$2',
        [newKey, custId]
      );
      await client.query('COMMIT');
    } catch(e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }

    // Revoke oude key in Redis
    await revokeKey(oldKey, 'rotated');

    // Cache nieuwe key alvast
    const cacheKey = 'wk:' + sha256(newKey);
    await redisSet(cacheKey, JSON.stringify({ id: custId, api_key: newKey, enabled: true }), 60);

    await logSecurityEvent('key_rotated', { customer_id: custId }).catch(function(){});

    return res.json({
      ok: true,
      api_key: newKey,
      snippet: `<script src="https://wall.paramant.app/snippet.js?k=${newKey}" async></script>`,
      message: 'Oude key direct ongeldig. Update snippet.js op je website.'
    });
  } catch(e) {
    console.error('[WALL:ERR] Key rotation error:', e.message);
    return res.status(500).json({ error: 'rotation_failed' });
  }
});

  const allowed = ['key_activated','key_revoked','rate_limit_hit','domain_blocked',
                   'invalid_key_attempt','gdpr_delete','webhook_received','pending_cleanup'];
  if (allowed.indexOf(eventType) < 0) return;
  try {
    await pg.query(
      'INSERT INTO system_events (id, event_type, meta, created_at) VALUES (gen_random_uuid(), $1, $2, NOW())',
      [eventType, JSON.stringify(meta || {})]
    );
  } catch(e) { /* non-blocking */ }
}

async function sendEmail(to, subject, html) {
  const POSTMARK_KEY = process.env.POSTMARK_API_KEY;
  if (!POSTMARK_KEY) {
    console.log('[WALL] EMAIL (no Postmark key):', subject, '->', to.slice(0,4)+'***');
    return false;
  }
  try {
    const https = require('https');
    const body = JSON.stringify({
      From: 'noreply@paramant.app',
      To: to,
      Subject: subject,
      HtmlBody: html,
      MessageStream: 'outbound'
    });
    await new Promise(function(resolve, reject) {
      const req = https.request({
        hostname: 'api.postmarkapp.com',
        path: '/email',
        method: 'POST',
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
          'X-Postmark-Server-Token': POSTMARK_KEY,
          'Content-Length': Buffer.byteLength(body)
        }
      }, function(res) {
        let data = '';
        res.on('data', function(c) { data += c; });
        res.on('end', function() {
          const d = JSON.parse(data);
          if (d.ErrorCode && d.ErrorCode !== 0) {
            reject(new Error('Postmark: ' + d.Message));
          } else {
            resolve(d);
          }
        });
      });
      req.on('error', reject);
      req.write(body);
      req.end();
    });
    console.log('[WALL] Email verzonden via Postmark:', subject, '->', to.slice(0,4)+'***');
    return true;
  } catch(e) {
    console.error('[WALL:ERR] Postmark error:', e.message.slice(0,80));
    return false;
  }
}

async function sendKeyInvalidationEmail(email, reason, newKeyHint) {
  const subject = 'PARAMANT WALL — Was jij dit? Je API key is veranderd';
  const html = `
<!DOCTYPE html><html><head><meta charset="utf-8"></head>
<body style="background:#0c0e10;color:#e2e4e8;font-family:monospace;padding:40px;max-width:540px;margin:0 auto">
  <div style="border:1px solid #1e2026;padding:32px">
    <div style="font-size:18px;font-weight:800;color:#00ff9d;margin-bottom:4px">PARAMANT WALL</div>
    <div style="font-size:11px;color:#5a6070;margin-bottom:24px;border-bottom:1px solid #1e2026;padding-bottom:16px">Beveiligingsmelding</div>
    <div style="font-size:13px;font-weight:700;color:#f5c400;margin-bottom:16px">⚠ Je API key is geïnvalideerd</div>
    <p style="font-size:11px;color:#8a8e98;line-height:1.8;margin-bottom:16px">
      Je PARAMANT WALL API key is zojuist gedeactiveerd.<br>
      <strong style="color:#e2e4e8">Reden:</strong> ${reason || 'Beveiligingsbeleid'}
    </p>
    <p style="font-size:11px;color:#8a8e98;line-height:1.8;margin-bottom:24px">
      Als jij dit was: je kunt een nieuwe key aanvragen via de recovery flow.<br>
      <strong style="color:#f87171">Was jij dit niet?</strong> Neem direct contact op via privacy@paramant.app
    </p>
    <a href="https://wall.paramant.app/recover" style="display:inline-block;padding:10px 20px;background:#00ff9d;color:#0c0e10;font-weight:800;font-size:11px;text-decoration:none;letter-spacing:.06em">→ KEY RECOVERY STARTEN</a>
    <p style="font-size:9px;color:#3d4149;margin-top:24px;border-top:1px solid #1e2026;padding-top:16px">
      PARAMANT · privacy@paramant.app · wall.paramant.app<br>
      Dit is een automatische beveiligingsmelding. Geen PII opgeslagen.
    </p>
  </div>
</body></html>`;
  return sendEmail(email, subject, html);
}

async function sendMagicLinkEmail(email, token) {
  const link = 'https://wall.paramant.app/recover?token=' + token;
  const subject = 'PARAMANT WALL — Je API key recovery link';
  const html = `
<!DOCTYPE html><html><head><meta charset="utf-8"></head>
<body style="background:#0c0e10;color:#e2e4e8;font-family:monospace;padding:40px;max-width:540px;margin:0 auto">
  <div style="border:1px solid #1e2026;padding:32px">
    <div style="font-size:18px;font-weight:800;color:#00ff9d;margin-bottom:4px">PARAMANT WALL</div>
    <div style="font-size:11px;color:#5a6070;margin-bottom:24px;border-bottom:1px solid #1e2026;padding-bottom:16px">Key Recovery</div>
    <p style="font-size:12px;color:#8a8e98;line-height:1.8;margin-bottom:24px">
      Klik op de knop hieronder om je API key op te halen.<br>
      <strong style="color:#f5c400">Deze link is 15 minuten geldig en kan slechts éénmaal gebruikt worden.</strong>
    </p>
    <a href="${link}" style="display:inline-block;padding:12px 24px;background:#00ff9d;color:#0c0e10;font-weight:800;font-size:11px;text-decoration:none;letter-spacing:.06em">→ OPEN KEY RECOVERY</a>
    <p style="font-size:9px;color:#3d4149;margin-top:24px;border-top:1px solid #1e2026;padding-top:16px">
      Niet aangevraagd? Negeer dit bericht veilig.<br>
      PARAMANT · privacy@paramant.app
    </p>
  </div>
</body></html>`;
  return sendEmail(email, subject, html);
}

async function requireCustomer(req, res, next) {
  const apiKey = (req.headers['x-wall-key'] || req.headers['x-api-key'] || req.query._wk || req.query.k || '').trim();
  const customer = await getCustomer(apiKey);
  if (!customer) return res.status(401).json({ error: 'invalid_key' });
  // Check revoked_keys tabel (harde invalidatie)
  try {
    const revokedKey = 'revoked:' + sha256(apiKey).slice(0,16);
    const isRevoked = await redis.get(revokedKey).catch(function(){ return null; });
    if (isRevoked) return res.status(401).json({ error: 'key_revoked' });
  } catch(e) {}
  // Domain lock: Origin + Referer check
  const _doms = Array.isArray(customer.allowed_domains) ? customer.allowed_domains.filter(function(x){ return x && x.length > 0; }) : [];
  if (_doms.length > 0) {
    const _clean = function(h) { return (h || '').replace(/^https?:\/\//, '').replace(/\/.*/, '').replace(/^www\./, '').toLowerCase().trim(); };
    const _origin  = _clean(req.headers['origin']);
    const _referer = _clean(req.headers['referer']);
    const _reqDom  = _origin || _referer;
    const _domOk   = _reqDom && _doms.some(function(d) {
      const _d = d.toLowerCase().trim();
      return _reqDom === _d || _reqDom.endsWith('.' + _d);
    });
    if (!_domOk) {
      logSecurityEvent('domain_blocked', {}).catch(function(){});
    return res.status(403).json({ error: 'domain_not_allowed', domain: _reqDom, allowed: _doms });
    }
  }
  req.customer = customer;
  req.apiKey   = apiKey;
  next();
}

function proxyRequest(upstream, method, headers, body) {
  return new Promise(function(resolve, reject) {
    const url  = new URL(upstream);
    const lib  = url.protocol === 'https:' ? https : http;
    const req  = lib.request({
      hostname: url.hostname,
      port:     url.port || (url.protocol === 'https:' ? 443 : 80),
      path:     url.pathname + url.search,
      method:   method || 'POST',
      headers:  headers || {},
      timeout:  5000,
    }, function(r) {
      let data = '';
      r.on('data', function(d) { data += d; });
      r.on('end', function() { resolve({ status: r.statusCode, body: data }); });
    });
    req.on('error', reject);
    req.on('timeout', function() { req.destroy(); reject(new Error('timeout')); });
    if (body) req.write(body);
    req.end();
  });
}

// Stats batch buffer — flush elke 5 seconden ipv per request
var _statsBuf = {};
function incStats(customerId, type) {
  var col = { blocked:'blocked', strip:'stripped', allow:'allowed' }[type] || 'allowed';
  var key = customerId + ':' + col;
  _statsBuf[key] = (_statsBuf[key] || 0) + 1;
}

// Flush stats buffer naar DB (batch update)
async function flushStatsBuf() {
  var buf = _statsBuf;
  _statsBuf = {};
  if (!Object.keys(buf).length) return;
  var month = new Date().toISOString().slice(0, 7);
  var client;
  try {
    client = await pg.connect();
    for (var key in buf) {
      if (!Object.prototype.hasOwnProperty.call(buf, key)) continue;
      var parts = key.split(':');
      var cid = parts[0];
      var col = parts[1];
      var cnt = buf[key];
      await client.query(
        'INSERT INTO usage_monthly (customer_id, month, requests, ' + col + ') VALUES ($1, $2, $3, $3) ON CONFLICT (customer_id, month) DO UPDATE SET requests = usage_monthly.requests + $3, ' + col + ' = usage_monthly.' + col + ' + $3',
        [cid, month, cnt]
      );
    }
  } catch(e) {
    console.error('[WALL:ERR] flushStats error:', e.code || e.message.slice(0,40));
  } finally {
    if (client) client.release();
  }
}
setInterval(flushStatsBuf, 5000);

// GA4 proxy
app.all('/proxy/ga4', requireCustomer, async function(req, res) {
  const { customer, apiKey } = req;
  const ip = getClientIP(req);

  const query = {};
  ['v','tid','gtm','en','ep','sid','sct','seg','dl','dr','dt']
    .forEach(function(p) { if (req.query[p]) query[p] = String(req.query[p]).slice(0, 200); });
  if (req.query.cid)       query.cid       = sha256(req.query.cid + dailySalt()).slice(0, 32);
  if (req.query.client_id) query.client_id = sha256(req.query.client_id + dailySalt()).slice(0, 32);
  query.uip = anonymizeIP(ip);

  let body;
  if (req.method === 'POST' && req.body) {
    try {
      let parsed = req.body;
      if (parsed.events) {
        parsed.events = parsed.events.map(function(ev) {
          const p = Object.assign({}, ev.params || {});
          ['user_id','email','phone','name','ip_override'].forEach(function(k) { delete p[k]; });
          return Object.assign({}, ev, { params: p });
        });
      }
      body = JSON.stringify(parsed);
    } catch { body = undefined; }
  }

  try {
    await proxyRequest(
      'https://www.google-analytics.com/mp/collect?' + new URLSearchParams(query).toString(),
      req.method,
      { 'Content-Type': 'application/json', 'User-Agent': anonymizeUA(req.headers['user-agent'] || '') },
      body
    );
    incStats(customer.id, 'allow');
    res.status(200).setHeader('X-Wall', VERSION).end();
  } catch {
    incStats(customer.id, 'blocked');
    res.status(502).json({ error: 'upstream_error' });
  }
});

// Meta proxy
app.all('/proxy/meta', requireCustomer, async function(req, res) {
  const { customer } = req;
  const ip = getClientIP(req);

  const query = {};
  ['id','ev'].forEach(function(p) { if (req.query[p]) query[p] = String(req.query[p]).slice(0, 200); });
  ['em','ph','fn','ln','db','ge','ct','st','zp','fbp','fbc','fbclid','external_id']
    .forEach(function(p) { delete query[p]; });
  query._anon = anonymizeIP(ip);

  incStats(customer.id, 'strip');

  try {
    await proxyRequest('https://www.facebook.com/tr?' + new URLSearchParams(query).toString(), 'GET', {});
    incStats(customer.id, 'allow');
    res.status(200).setHeader('X-Wall', VERSION).end();
  } catch {
    res.status(502).json({ error: 'upstream_error' });
  }
});

// ── Snippet serveren ──────────────────────────────────────────────
app.get('/snippet.js', function(req, res) {
  // Snippet mag geserveerd worden zonder auth - key zit in de JS zelf
  res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
  res.setHeader('Cache-Control', 'public, max-age=7200, s-maxage=7200'); // 2 uur — consistent met Cloudflare Page Rule
  res.setHeader('Access-Control-Allow-Origin', '*'); // Snippet moet van elke site geladen worden
  res.sendFile(require('path').join(__dirname, 'public', 'snippet.js'));
});


// ── Static files ──────────────────────────────────────────────────
// ── Security middleware ──────────────────────────────────────────
// Blokkeer OPTIONS en TRACE
app.use(function(req, res, next) {
  if (req.method === 'OPTIONS' || req.method === 'TRACE') {
    return res.status(405).json({ error: 'method_not_allowed' });
  }
  next();
});
// Prototype pollution bescherming — blokkeer ipv sanitize
app.use(function(req, res, next) {
  if (req.body) {
    const body_str = JSON.stringify(req.body);
    if (body_str.includes('__proto__') ||
        body_str.includes('constructor') ||
        body_str.includes('prototype')) {
      return res.status(400).json({ error: 'invalid_input' });
    }
  }
  next();
});

// Path traversal bescherming op query params
app.use(function(req, res, next) {
  const url = req.url || '';
  if (url.includes('..') || url.includes('%2e%2e') || url.includes('%252e')) {
    return res.status(400).json({ error: 'invalid_path' });
  }
  // Blokkeer null bytes
  if (url.includes('%00') || url.includes('\0')) {
    return res.status(400).json({ error: 'invalid_path' });
  }
  next();
});

app.use(express.static(path.join(__dirname, 'public')));
app.get('/privacy',  function(req, res) { res.sendFile(path.join(__dirname, 'public', 'privacy.html')); });
app.get('/recover', function(req, res) { res.sendFile(path.join(__dirname, 'public', 'recover.html')); });

// Server-side captcha genereren
app.get('/api/captcha', async function(req, res) {
  const ip = getClientIP(req);
  const ipKey = 'captcha_rl:' + sha256(ip).slice(0, 16);
  const cnt = parseInt(await redisGet(ipKey) || 0) || 0;
  if (cnt > 50) return res.status(429).json({ error: 'rate_limit' });
  await redisSet(ipKey, String(cnt + 1), 3600);

  const a = Math.floor(Math.random() * 9) + 1;
  const b = Math.floor(Math.random() * 9) + 1;
  const answer = a + b;
  const token = require('crypto').randomBytes(16).toString('hex');
  const tokenHash = sha256(token);

  // Sla antwoord op in Redis — 5 minuten geldig, eenmalig
  await redisSet('captcha:' + tokenHash, String(answer), 300);

  res.json({ token: token, question: a + ' + ' + b + ' = ?' });
});

// Server-side captcha verificatie endpoint
app.post('/api/captcha/verify', async function(req, res) {
  const { token, answer } = req.body || {};
  const valid = await validateCaptcha(token, answer);
  if (valid) {
    return res.json({ ok: true });
  }
  return res.json({ ok: false });
});

// Server-side captcha valideren
async function validateCaptcha(token, answer) {
  if (!token || !answer) return false;
  const tokenHash = sha256(token);
  const stored = await redisGet('captcha:' + tokenHash);
  if (!stored) return false;
  // Eenmalig — verwijder na gebruik
  await redis.del('captcha:' + tokenHash).catch(() => {});
  return String(stored) === String(answer);
}

// CSRF token endpoint voor recover + gdpr formulieren
app.get('/api/csrf-token', function(req, res) {
  const token = require('crypto').randomBytes(32).toString('hex');
  const tokenHash = sha256(token);
  // Sla op in Redis — 1 uur geldig
  redisSet('csrf:' + tokenHash, '1', 3600);
  res.json({ token: token });
});

// CSRF validatie middleware
async function validateCSRF(req, res, next) {
  const csrfToken = req.headers['x-csrf-token'] || (req.body || {}).csrf_token;
  if (!csrfToken) {
    // Graceful degradatie — log maar blokkeer niet (backwards compat)
    return next();
  }
  const tokenHash = sha256(csrfToken);
  const valid = await redisGet('csrf:' + tokenHash);
  if (!valid) {
    return res.status(403).json({ error: 'invalid_csrf_token' });
  }
  // Single use
  await redis.del('csrf:' + tokenHash).catch(() => {});
  next();
}
app.get('/cancel',   function(req, res) { res.sendFile(path.join(__dirname, 'public', 'cancel.html')); });

// ── Health / Stats ────────────────────────────────────────────────
app.get('/api/trackers', async function(req, res) {
  // Rate limit: max 30/uur per IP
  const trkKey = 'trackers_rl:' + sha256(getClientIP(req)).slice(0, 16);
  const trkCnt = parseInt(await redisGet(trkKey) || 0) || 0;
  if (trkCnt > 30) return res.status(429).json({ error: 'rate_limit' });
  await redisSet(trkKey, String(trkCnt + 1), 3600);
  res.json({
    ok: true,
    trackers: BUILT_IN_TRACKERS,
    templates: Object.entries(TEMPLATES).map(([key, t]) => ({
      key,
      label: t.label,
      description: t.description,
    })),
    categories: TRACKER_CATEGORIES,
  });
});

app.post('/api/gdpr/delete', async function(req, res) {
  // Rate limit: max 3 per uur per IP
  const gdprIp = getClientIP(req);
  const gdprKey = 'gdpr_rl:' + require('crypto').createHash('sha256').update(gdprIp).digest('hex').slice(0,16);
  const gdprCount = parseInt(await redisGet(gdprKey) || 0) || 0;
  if (gdprCount >= 3) {
    logSecurityEvent('rate_limit_hit', {}).catch(function(){});
    return res.status(429).json({ error: 'rate_limit', retry_after: 3600 });
  }
  await redisSet(gdprKey, String(gdprCount + 1), 3600);
  const { email, apiKey } = req.body || {};
  if (!email && !apiKey) return res.status(400).json({ error: 'email_or_key_required' });
  try {
    let userId = null;
    if (apiKey) {
      const r = await pg.query('SELECT user_id FROM customers WHERE api_key = $1 LIMIT 1', [apiKey]);
      if (r.rows.length) userId = r.rows[0].user_id;
    }
    if (!userId && email) {
      const r = await pg.query('SELECT id FROM users WHERE email = $1 AND deleted_at IS NULL LIMIT 1', [email]);
      if (r.rows.length) userId = r.rows[0].id;
    }
    if (!userId) {
      // Altijd zelfde response — geen account enumeration
      return res.json({ ok: true, message: 'Als dit account bestaat, ontvang je een bevestigingsmail.' });
    }

    // Genereer bevestigingstoken — geldig 1 uur
    const deleteToken = require('crypto').randomBytes(32).toString('hex');
    const deleteTokenHash = sha256(deleteToken);
    await redisSet('gdpr_confirm:' + deleteTokenHash, String(userId), 3600);

    // Stuur bevestigingsmail
    const confirmUrl = 'https://wall.paramant.app/api/gdpr/confirm?token=' + deleteToken;
    const emailTo = email || '';
    if (emailTo) {
      const html = `
        <div style="font-family:monospace;background:#0c0e10;color:#e2e4e8;padding:24px;max-width:480px">
          <div style="font-size:11px;color:#5a6070;letter-spacing:.1em;margin-bottom:8px">// PARAMANT WALL</div>
          <div style="font-size:16px;font-weight:800;color:#e2e4e8;margin-bottom:16px">Account verwijderen</div>
          <p style="font-size:12px;color:#8a8e98;line-height:1.8;margin-bottom:20px">
            We hebben een verzoek ontvangen om jouw account te verwijderen.<br>
            <strong style="color:#f87171">Als jij dit niet was, doe dan niets. De link vervalt na 1 uur.</strong>
          </p>
          <a href="\${confirmUrl}" style="display:inline-block;padding:12px 24px;background:#f87171;color:#0c0e10;font-weight:800;font-size:12px;text-decoration:none;letter-spacing:.06em">
            → BEVESTIG ACCOUNT VERWIJDERING
          </a>
          <p style="font-size:11px;color:#5a6070;margin-top:20px;line-height:1.7">
            Na bevestiging worden alle gegevens permanent verwijderd.<br>
            Je API key wordt direct ongeldig.<br>
            Dit kan niet ongedaan gemaakt worden.
          </p>
        </div>
      `;
      await sendEmail(emailTo, 'PARAMANT WALL — Bevestig account verwijdering', html);
    }
    return res.json({ ok: true, message: 'Account verwijderd. Alle persoonsgegevens zijn gewist.' });
  } catch(e) {
    console.error('[WALL:ERR] GDPR delete error:', e.code || e.message.slice(0, 50));
    return res.status(500).json({ error: 'delete_failed' });
  }
});

app.all('/proxy/generic', requireCustomer, async function(req, res) {
  const { customer } = req;
  const origUrl = req.query._orig || req.headers['x-wall-original'] || '';
  if (!origUrl) return res.json({ ok: true, action: 'dropped', reason: 'no_original_url' });

  // Check tracker config voor dit domein
  const ip = getClientIP(req);
  const ipHash = sha256(ip + new Date().toISOString().slice(0,10) + (process.env.IP_SALT||'wall')).slice(0,16);

  // Strip PII uit query string
  let cleanUrl = origUrl;
  const piiParams = ['client_id','user_id','_ga','_gid','_fbc','_fbp','uid','email','phone'];
  try {
    const u = new URL(origUrl);
    piiParams.forEach(function(p) { u.searchParams.delete(p); });
    cleanUrl = u.toString();
  } catch(e) {}

  // Haal tracker actie op via config
  let action = 'block'; // default: block voor generieke trackers
  try {
    const cfgRow = await pg.query(
      'SELECT config_json FROM wall_configs WHERE customer_id=$1 LIMIT 1', [customer.id]
    );
    if (cfgRow.rows.length > 0) {
      const cfg = JSON.parse(cfgRow.rows[0].config_json || '{}');
      // Zoek matching tracker in config
      // (simplified - full matching in trackers.js)
      action = cfg.default_action || 'block';
    }
  } catch(e) {}

  await incStats(customer.id, action === 'block' ? 'blocked' : action === 'strip' ? 'strip' : 'allow');

  if (action === 'block') {
    return res.status(200).json({ ok: true, action: 'blocked', url: origUrl.slice(0,50) });
  }

  if (action === 'allow' || action === 'strip') {
    try {
      const result = await proxyRequest(cleanUrl, req.method, {
        'content-type': req.headers['content-type'] || 'application/json',
        'user-agent': 'PARAMANT-WALL/3.2.0',
      }, req.body ? JSON.stringify(req.body) : undefined);
      return res.status(result.status).send(result.body);
    } catch(e) {
      return res.json({ ok: true, action: 'forwarded_error' });
    }
  }

  return res.json({ ok: true, action: 'processed' });
});


app.post('/api/auth/recover', async function(req, res) {
  const email = ((req.body || {}).email || '').toLowerCase().trim();
  if (!email || email.indexOf('@') < 1) return res.status(400).json({ error: 'invalid_email' });

  // Rate limit: max 3 recovery attempts per uur per email
  const emailHash = sha256(email).slice(0, 20);
  const rlKey     = 'recover_rl:' + emailHash;
  const rlCnt     = parseInt(await redisGet(rlKey) || 0) || 0;
  if (rlCnt >= 5) return res.status(429).json({ error: 'rate_limit', retry_after: 900 });
  await redisSet(rlKey, String(rlCnt + 1), 900);

  // Jitter: voorkomt timing attack (gelijke responstijd of email bestaat of niet)
  await randomJitter(50, 200);

  // Check of email bestaat (geen enumeration — altijd 200)
  const userRow = await pg.query(
    'SELECT u.id, c.api_key FROM users u JOIN customers c ON c.user_id=u.id WHERE u.email=$1 AND c.enabled=true AND u.deleted_at IS NULL LIMIT 1',
    [email]
  ).catch(function(){ return { rows: [] }; });

  if (userRow.rows.length > 0) {
    // Genereer magic link token
    const token     = require('crypto').randomBytes(32).toString('hex');
    const tokenHash = sha256(token);
    await pg.query(
      "INSERT INTO magic_links (id, user_id, token_hash, expires_at, used) VALUES (gen_random_uuid(), , , NOW() + INTERVAL '15 minutes', false)",
      [userRow.rows[0].id, tokenHash]
    ).catch(function(){});

    // Stuur email
    if (typeof sendEmail === 'function') {
      const link = 'https://wall.paramant.app/recover?token=' + token;
      const html = `<!DOCTYPE html><html><head><meta charset="utf-8"></head>
<body style="background:#0c0e10;color:#e2e4e8;font-family:monospace;padding:32px;max-width:520px;margin:0 auto">
<div style="border:1px solid #1e2026;padding:28px">
  <div style="font-size:16px;font-weight:800;color:#00ff9d;margin-bottom:16px">PARAMANT WALL</div>
  <div style="font-size:12px;font-weight:700;color:#e2e4e8;margin-bottom:12px">Je API key recovery link</div>
  <p style="font-size:11px;color:#8a8e98;line-height:1.8;margin-bottom:8px">
    Klik op de knop om je API key op te halen.<br>
    <strong style="color:#f5c400">Geldig: 15 minuten &middot; Eenmalig gebruik</strong>
  </p>
  <a href="${link}" style="display:inline-block;padding:12px 24px;background:#00ff9d;color:#0c0e10;font-weight:800;font-size:11px;text-decoration:none;letter-spacing:.06em;margin:16px 0">OPEN KEY RECOVERY &rarr;</a>
  <p style="font-size:9px;color:#3d4149;margin-top:16px;border-top:1px solid #1e2026;padding-top:12px">
    Niet aangevraagd? Negeer dit bericht.<br>
    PARAMANT &middot; privacy@paramant.app
  </p>
</div></body></html>`;
      await sendEmail(email, 'PARAMANT WALL — Je key recovery link', html);
    }
  }

  // Track mislukte pogingen voor CAPTCHA trigger
  if (!userRow.rows.length) {
    const failKey = 'recover_fail:' + sha256(getClientIP(req)).slice(0, 16);
    const failCnt = parseInt(await redisGet(failKey) || 0) + 1;
    await redisSet(failKey, String(failCnt), 3600);
    if (failCnt >= 5) {
      // Flag dit IP voor verhoogde controle
      await logSecurityEvent('recover_suspicious', { ipHash: sha256(getClientIP(req)).slice(0, 16), attempts: failCnt }).catch(() => {});
    }
  }

  // Altijd 200 (geen email enumeration)
  return res.json({ ok: true, message: 'Als dit e-mailadres bekend is, ontvang je een link.' });
});

// ── GDPR Delete bevestiging via token ───────────────────────────
app.get('/api/gdpr/confirm', async function(req, res) {
  const token = (req.query.token || '').trim();
  if (!token || token.length < 32) {
    return res.status(400).send('<h2>Ongeldige of verlopen link.</h2>');
  }
  const tokenHash = sha256(token);
  const userId = await redisGet('gdpr_confirm:' + tokenHash);
  if (!userId) {
    return res.status(400).send(`
      <html><body style="font-family:monospace;background:#0c0e10;color:#e2e4e8;padding:40px;text-align:center">
        <h2 style="color:#f87171">[!] Link verlopen of al gebruikt.</h2>
        <p style="color:#8a8e98;margin-top:12px">Dien een nieuw verwijderverzoek in als je account nog bestaat.</p>
        <a href="/" style="color:#00ff9d">← Terug</a>
      </body></html>
    `);
  }

  try {
    // Voer de echte delete uit
    await pg.query('UPDATE users SET deleted_at = NOW(), email = $1 WHERE id = $2',
      ['deleted_' + require('crypto').randomBytes(8).toString('hex') + '@deleted', userId]);
    await pg.query('UPDATE customers SET enabled = false WHERE user_id = $1', [userId]);

    // GDPR audit trail
    const userHash = sha256(userId).slice(0, 16);
    await pg.query(
      'INSERT INTO gdpr_deletions (id, user_hash, deleted_at, reason) VALUES (gen_random_uuid(), $1, NOW(), $2)',
      [userHash, 'user_confirmed']
    ).catch(() => {});

    // Verwijder token + cache
    await redisSet('gdpr_confirm:' + tokenHash, 'used', 1);
    redis.del('wk:' + userId).catch(() => {});

    await logSecurityEvent('gdpr_delete', { userHash }).catch(() => {});

    return res.send(`
      <html><body style="font-family:monospace;background:#0c0e10;color:#e2e4e8;padding:40px;text-align:center;max-width:520px;margin:0 auto">
        <h2 style="color:#00ff9d">[OK] Verwijdering gepland.</h2>
        <p style="color:#8a8e98;margin-top:12px;line-height:1.8">
          Je account en alle gegevens worden over <strong style="color:#f5c400">7 dagen</strong> permanent verwijderd.<br>
          Je API key is direct ongeldig.<br><br>
          Heb je je bedacht? Stuur een email naar
          <a href="mailto:privacy@paramant.app" style="color:#00ff9d">privacy@paramant.app</a>
          binnen 7 dagen om de verwijdering te annuleren.
        </p>
        <a href="/" style="color:#00ff9d;display:inline-block;margin-top:20px">← Terug naar home</a>
      </body></html>
    `);
  } catch(e) {
    console.error('[WALL:ERR] GDPR confirm error:', e.message);
    return res.status(500).send('<h2>Er ging iets mis. Neem contact op via privacy@paramant.app</h2>');
  }
});

app.get('/api/auth/recover', async function(req, res) {
  const token = (req.query.token || '').trim();
  if (!token || token.length < 60) return res.status(400).json({ error: 'invalid_token' });

  const tokenHash = sha256(token);
  const row = await pg.query(
    'SELECT ml.user_id, ml.used, ml.expires_at, c.api_key FROM magic_links ml JOIN customers c ON c.user_id=ml.user_id WHERE ml.token_hash=$1 AND c.enabled=true LIMIT 1',
    [tokenHash]
  ).catch(function(){ return { rows: [] }; });

  if (!row.rows.length) return res.status(404).json({ error: 'token_not_found' });
  const ml = row.rows[0];
  if (ml.used) return res.status(410).json({ error: 'token_used' });
  if (new Date(ml.expires_at) < new Date()) return res.status(410).json({ error: 'token_expired' });

  // Markeer als gebruikt
  await pg.query('UPDATE magic_links SET used=true WHERE token_hash=$1', [tokenHash]).catch(function(){});

  return res.json({ ok: true, api_key: ml.api_key });
});



// Fail hard bij ontbrekende kritieke env vars
const REQUIRED_ENV = ['DATABASE_URL', 'STRIPE_SECRET_KEY', 'SESSION_SECRET'];
REQUIRED_ENV.forEach(function(k) {
  if (!process.env[k]) {
    console.error('[WALL] KRITIEK: Ontbrekende env var:', k);
    process.exit(1);
  }
});

app.get('/api/version', function(req, res) {
  return res.status(404).json({ error: 'not_found' });
  if (false) {
  res.setHeader('Cache-Control', 'public, max-age=3600');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.json({
    ok: true,
    server_version: '4.0.0',
    snippet_version: '4.0.0',
    min_snippet:     '3.4.0',
  });
});

app.get('/health', function(req, res) {
  res.json({ ok: true });
});

app.get('/stats', function(req, res) { return res.status(404).json({ error: 'not_found' }); });


app.use(function(req, res) { res.status(404).json({ error: 'not_found' }); });
app.use(function(err, req, res, next) { res.status(500).json({ error: 'internal_error' }); });

// ── Start ─────────────────────────────────────────────────────────
http.createServer(app).listen(PORT, '127.0.0.1', function() {

});

// Graceful shutdown
['SIGTERM','SIGINT'].forEach(function(sig) {
  process.once(sig, async function() {
    console.log('[WALL] Graceful shutdown:', sig);
    try {
      await flushStatsBuf(); // Flush stats voor shutdown
      await pg.end();
      await redis.quit();
    } catch(e) {}
    process.exit(0);
  });
});
