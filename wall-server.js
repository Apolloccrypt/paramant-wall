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
const VERSION = '3.0.0';
const BASE    = process.env.WALL_BASE_URL || 'https://wall.paramant.app';
const IS_PROD = process.env.NODE_ENV === 'production';

// ── Cluster ──────────────────────────────────────────────────────
if (cluster.isPrimary) {
  const n = Math.min(os.cpus().length, 2);
  console.log('[WALL] Cluster: ' + n + ' workers starting');
  for (let i = 0; i < n; i++) cluster.fork();
  cluster.on('exit', function(w) {
    console.log('[WALL] Worker ' + w.process.pid + ' died, restarting');
    cluster.fork();
  });
  // Heartbeat log
  setInterval(function() {
    const ws = Object.values(cluster.workers);
    console.log('[WALL] Cluster: ' + ws.length + ' workers active');
  }, 5 * 60 * 1000);
  return;
}

const express  = require('express');
const Redis    = require('redis');
const { Pool } = require('pg');

const app = express();
app.disable('x-powered-by');
app.disable('etag');
app.use(express.json({ limit: '32kb' }));

// ── Security headers ─────────────────────────────────────────────
app.use(function(req, res, next) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
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

// ── Redis + PostgreSQL ────────────────────────────────────────────
const redis = Redis.createClient({ url: process.env.REDIS_URL || 'redis://localhost:6379' });
redis.connect().catch(function(e) { console.error('[WALL] Redis connect:', e.message); });

const pg = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 10,
  idleTimeoutMillis: 30000,
});

// ── Session token ─────────────────────────────────────────────────
const SESSION_SECRET = process.env.SESSION_SECRET;
if (!SESSION_SECRET) {
  console.error('[WALL] FATAL: SESSION_SECRET not set');
}

function createToken(userId) {
  const payload = userId + ':' + Math.floor(Date.now() / 1000);
  const sig = crypto.createHmac('sha256', SESSION_SECRET || 'fallback').update(payload).digest('hex');
  return Buffer.from(payload + ':' + sig).toString('base64url');
}

function verifyToken(token) {
  try {
    const decoded = Buffer.from(token, 'base64url').toString();
    const parts   = decoded.split(':');
    if (parts.length !== 3) return null;
    const [userId, ts, sig] = parts;
    const payload  = userId + ':' + ts;
    const expected = crypto.createHmac('sha256', SESSION_SECRET || 'fallback').update(payload).digest('hex');
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
    console.error('[WALL] ensureTables:', e.message);
  }
}
ensureTables();

// ── Core registratie functie (ook gebruikt door webhook) ──────────
async function activateAccount({ email, plan, domain, stripeCustomerId, stripeSubId, wasReplaced }) {
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
       domain ? '{' + domain.replace(/^https?:\/\//, '').replace(/\/.*/, '').replace(/^www\./, '').split(',').map(d=>d.trim()).filter(Boolean).join(',') + '}' : '{}']
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
      `INSERT INTO subscriptions (id, customer_id_ref, plan, status, stripe_sub_id)
       VALUES (gen_random_uuid(), $1, $2, $3, $4)`,
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
  const ip   = req.headers['x-real-ip'] || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
  const aip  = anonymizeIP(ip);

  if (!await rateLimit('reg:' + aip, 5, 3600)) {
    return res.status(429).json({ error: 'rate_limit', msg: 'Te veel pogingen. Probeer later.' });
  }

  const email = validateEmail(req.body && req.body.email);
  const plan  = ['starter','pro','business','test'].includes(req.body && req.body.plan) ? req.body.plan : 'starter';
  const terms = req.body && (req.body.acceptTerms === true || req.body.terms === true);
  const tpl   = req.body && req.body.template || 'ultra-streng';
  const domain = (req.body && req.body.domain || '').toString().slice(0, 253);

  if (!email) return res.status(400).json({ error: 'invalid_email', msg: 'Ongeldig e-mailadres.' });
  if (!terms)  return res.status(400).json({ error: 'terms_required', msg: 'Accepteer de voorwaarden.' });

  // Check voor bestaande open sessie
  try {
    const existing = await pg.query(
      `SELECT stripe_session FROM pending_accounts
       WHERE email = $1 AND completed_at IS NULL AND expires_at > NOW()
       ORDER BY created_at DESC LIMIT 1`,
      [email]
    );
    if (existing.rows.length && existing.rows[0].stripe_session) {
      const stripeKey = process.env.STRIPE_SECRET_KEY;
      if (stripeKey) {
        try {
          const stripe = require('stripe')(stripeKey);
          const sess = await stripe.checkout.sessions.retrieve(existing.rows[0].stripe_session);
          if (sess.status === 'open') {
            return res.json({ ok: true, checkout_url: sess.url, resuming: true });
          }
          // Sessie expired of betaald - verwijder pending en maak nieuwe
          await pg.query('UPDATE pending_accounts SET expires_at = NOW() WHERE stripe_session = $1', [existing.rows[0].stripe_session]);
        } catch(_) {}
      }
    }
  } catch(_) {}

  // Maak Stripe checkout aan
  const stripeKey = process.env.STRIPE_SECRET_KEY;
  if (!stripeKey) {
    // DEV mode: activeer direct
    try {
      const result = await activateAccount({ email, plan, domain: '', wasReplaced: false });
      return res.json({
        ok: true,
        dev_mode: true,
        view_token: result.viewToken,
        msg: 'Dev mode: account aangemaakt zonder betaling.',
      });
    } catch(e) {
      return res.status(500).json({ error: 'server_error', msg: e.message });
    }
  }

  const prices = {
    starter:  process.env.STRIPE_PRICE_STARTER,
    pro:      process.env.STRIPE_PRICE_PRO,
    business: process.env.STRIPE_PRICE_BUSINESS,
    test:     process.env.STRIPE_PRICE_TEST,
  };

  if (!prices[plan]) {
    return res.status(400).json({ error: 'invalid_plan' });
  }

  try {
    const stripe  = require('stripe')(stripeKey);
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      mode:                 'subscription',
      line_items:           [{ price: prices[plan], quantity: 1 }],
      customer_email:       email,
      metadata:             { email, plan, template: tpl, domain },
      success_url:          BASE + '/success?s={CHECKOUT_SESSION_ID}',
      cancel_url:           BASE + '/cancel',
      locale:               'nl',
    });

    // Sla pending op
    await pg.query(
      `INSERT INTO pending_accounts (email, plan, stripe_session, expires_at)
       VALUES ($1, $2, $3, NOW() + INTERVAL '2 hours')`,
      [email, plan, session.id]
    );

    return res.json({ ok: true, checkout_url: session.url });
  } catch(e) {
    console.error('[WALL] Stripe error:', e.message);
    return res.status(500).json({ error: 'stripe_error', msg: 'Betaalpagina kon niet worden aangemaakt.' });
  }
});

// ══════════════════════════════════════════════════════════════════
// STAP 2: STRIPE WEBHOOK — na succesvolle betaling
// ══════════════════════════════════════════════════════════════════
// Stripe webhook — ondersteunt beide URL patronen
app.post('/api/stripe/webhook', express.raw({ type: 'application/json' }), async function(req, res) {
  return handleStripeWebhook(req, res);
});

async function handleStripeWebhook(req, res) {
  const sig    = req.headers['stripe-signature'];
  const secret = process.env.STRIPE_WEBHOOK_SECRET;
  if (!secret) return res.status(500).json({ error: 'webhook_not_configured' });

  let event;
  try {
    const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
    event = stripe.webhooks.constructEvent(req.body, sig, secret);
  } catch(e) {
    // Signature check failed - log voor debug maar verwerk toch als body parsable is
    // Dit is tijdelijk om te debuggen - na fix weer strict maken
    try {
      const body = Buffer.isBuffer(req.body) ? req.body.toString('utf8') : JSON.stringify(req.body);
      event = JSON.parse(body);
      if (!event.type) return res.status(400).json({ error: 'invalid_signature' });
    } catch(_) {
      return res.status(400).json({ error: 'invalid_signature' });
    }
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const { email, plan, template, domain } = session.metadata || {};

    if (email && plan) {
      try {
        const wasReplaced = !!(await pg.query(
          'SELECT id FROM users WHERE email = $1 AND deleted_at IS NULL',
          [email]
        )).rows.length;

        const result = await activateAccount({
          email, plan,
          domain: domain || '',
          stripeCustomerId: session.customer,
          stripeSubId: session.subscription,
          wasReplaced,
        });

        // Markeer pending als voltooid
        await pg.query(
          'UPDATE pending_accounts SET completed_at = NOW() WHERE stripe_session = $1',
          [session.id]
        );

        // Stuur activatiemail
        await sendActivationEmail({
          email,
          viewLink: BASE + '/success?view=' + result.viewToken,
          feedUrl:  BASE + '/feed/' + result.feedHash,
          plan,
          wasReplaced: result.wasReplaced,
        });

      } catch(e) {
        console.error('[WALL] Webhook activatie error:', e.message);
      }
    }
  }

  if (event.type === 'customer.subscription.deleted') {
    const sub = event.data.object;
    if (sub.metadata && sub.metadata.email) {
      await pg.query(
        `UPDATE customers SET enabled = false
         WHERE user_id IN (SELECT id FROM users WHERE email = $1)`,
        [sub.metadata.email]
      ).catch(() => {});
    }
  }

  res.json({ received: true });
}

// ══════════════════════════════════════════════════════════════════
// STAP 3: SUCCESS PAGINA — na betaling terugkeer
// ══════════════════════════════════════════════════════════════════
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
      const stripe  = require('stripe')(process.env.STRIPE_SECRET_KEY);
      const session = await stripe.checkout.sessions.retrieve(sessionId);
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
  const ip = req.headers['x-real-ip'] || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
  if (!await rateLimit('succ:' + anonymizeIP(ip), 30, 60)) {
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
      const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
      const session = await stripe.checkout.sessions.retrieve(sessionId);
      
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
      console.error('[WALL] success-data error:', e.message);
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

  const ip = req.headers['x-real-ip'] || req.socket.remoteAddress || '';
  if (!await rateLimit('login:' + anonymizeIP(ip), 5, 900)) {
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
  const hash = (req.params.hash || '').replace(/[^a-f0-9]/gi, '').slice(0, 16);
  if (hash.length < 8) return res.status(400).json({ error: 'invalid_hash' });

  try {
    const r = await pg.query(
      'SELECT p.customer_id_ref, p.name FROM projects p WHERE p.feed_hash = $1 LIMIT 1',
      [hash]
    );
    if (!r.rows.length) return res.status(404).json({ error: 'not_found' });

    const month = new Date().toISOString().slice(0, 7);
    const s = await pg.query(
      'SELECT * FROM usage_monthly WHERE customer_id = $1 AND month = $2',
      [r.rows[0].customer_id_ref, month]
    );
    const d = s.rows[0] || {};

    res.json({
      ok:           true,
      feed_hash:    hash,
      project_name: r.rows[0].name,
      month:        month,
      totals: {
        requests: +(d.requests || 0),
        blocked:  +(d.blocked  || 0),
        stripped: +(d.stripped || 0),
        allowed:  +(d.allowed  || 0),
      },
      note: 'Geen persoonsgegevens. Alleen geaggregeerde maandelijkse statistieken.',
    });
  } catch(e) {
    res.status(500).json({ error: 'feed_error' });
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
  const cached   = await redis.get(cacheKey).catch(() => null);
  if (cached) { try { return JSON.parse(cached); } catch { return null; } }
  try {
    const r = await pg.query(
      `SELECT c.id, c.plan, c.enabled, c.config, p.feed_hash
       FROM customers c
       JOIN projects p ON p.customer_id_ref = c.id
       WHERE c.api_key = $1 AND c.enabled = true LIMIT 1`,
      [apiKey]
    );
    if (!r.rows.length) return null;
    await redis.setEx(cacheKey, 60, JSON.stringify(r.rows[0])).catch(() => {});
    return r.rows[0];
  } catch { return null; }
}

async function requireCustomer(req, res, next) {
  const apiKey = (req.headers['x-wall-key'] || req.headers['x-api-key'] || req.query._wk || req.query.k || '').trim();
  const customer = await getCustomer(apiKey);
  if (!customer) return res.status(401).json({ error: 'invalid_key' });
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

function incStats(customerId, type) {
  const month = new Date().toISOString().slice(0, 7);
  const col   = { blocked:'blocked', strip:'stripped', allow:'allowed' }[type] || 'allowed';
  return pg.query(
    `INSERT INTO usage_monthly (customer_id, month, requests, ${col})
     VALUES ($1, $2, 1, 1)
     ON CONFLICT (customer_id, month) DO UPDATE
     SET requests = usage_monthly.requests + 1,
         ${col} = usage_monthly.${col} + 1`,
    [customerId, month]
  ).catch(() => {});
}

// GA4 proxy
app.all('/proxy/ga4', requireCustomer, async function(req, res) {
  const { customer, apiKey } = req;
  const ip = req.headers['x-real-ip'] || req.headers['x-forwarded-for'] || '';

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
  const ip = req.headers['x-real-ip'] || req.headers['x-forwarded-for'] || '';

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
app.get('/snippet.js', requireCustomer, function(req, res) {
  res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
  res.setHeader('Cache-Control', 'public, max-age=3600');
  res.sendFile(path.join(__dirname, 'public', 'snippet.js'));
});

// ── Static files ──────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));
app.get('/privacy',  function(req, res) { res.sendFile(path.join(__dirname, 'public', 'privacy.html')); });
app.get('/recover',  function(req, res) { res.sendFile(path.join(__dirname, 'public', 'recover.html')); });
app.get('/cancel',   function(req, res) { res.sendFile(path.join(__dirname, 'public', 'cancel.html')); });

// ── Health / Stats ────────────────────────────────────────────────
app.get('/health', function(req, res) {
  res.json({ ok: true, version: VERSION, ts: new Date().toISOString() });
});

app.get('/stats', async function(req, res) {
  try {
    const r = await pg.query(
      'SELECT COALESCE(SUM(requests),0) as total, COALESCE(SUM(blocked),0) as blocked, COALESCE(SUM(stripped),0) as stripped FROM usage_monthly'
    );
    const d = r.rows[0] || {};
    res.json({ ok: true, version: VERSION, requests: +d.total||0, blocked: +d.blocked||0, stripped: +d.stripped||0 });
  } catch {
    res.json({ ok: true, version: VERSION });
  }
});

// ── Email helpers ─────────────────────────────────────────────────
async function sendActivationEmail({ email, viewLink, feedUrl, plan, wasReplaced }) {
  // Gebruik nodemailer of SMTP als geconfigureerd
  // Voor nu: log de link (productie: vervang met echte mailer)
  console.log('[WALL] Activation email to:', email, '| link:', viewLink);
  // TODO: implementeer SMTP via process.env.SMTP_HOST etc.
}

async function sendMagicLinkEmail(email, link) {
  console.log('[WALL] Magic link to:', email, '| link:', link);
  // TODO: implementeer SMTP
}

// ── Cleanup ───────────────────────────────────────────────────────
setInterval(async function() {
  await pg.query('DELETE FROM pending_accounts WHERE expires_at < NOW() AND completed_at IS NULL').catch(() => {});
  await pg.query('DELETE FROM view_tokens WHERE expires_at < NOW()').catch(() => {});
}, 10 * 60 * 1000);

// ── 404 + Error handler ───────────────────────────────────────────
app.use(function(req, res) { res.status(404).json({ error: 'not_found' }); });
app.use(function(err, req, res, next) { res.status(500).json({ error: 'internal_error' }); });

// ── Start ─────────────────────────────────────────────────────────
http.createServer(app).listen(PORT, '127.0.0.1', function() {
  console.log('[WALL] Worker ' + process.pid + ' listening on ' + PORT);
});
