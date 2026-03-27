# PARAMANT WALL — Developer README

> **Private repository. Proprietary software. All rights reserved.**
> © 2026 PARAMANT — Do not distribute or reproduce without explicit written permission.

---

## What is PARAMANT WALL?

PARAMANT WALL is a **privacy proxy SaaS** for website owners. It intercepts outbound browser tracking requests (analytics pixels, ad scripts, fingerprinting) before they leave the visitor's browser — replacing them with privacy-safe alternatives or dropping them entirely.

**Value proposition in one line:**  
Website owners subscribe to a plan. Their visitors are protected silently — no install, no awareness, no cost to the visitor.

---

## Architecture Overview

```
Visitor browser
     │
     ▼
Cloudflare (DNS + TLS termination + WAF)
     │
     ▼
Nginx (reverse proxy, port 443 → 127.0.0.1:4000)
     │
     ▼
Node.js cluster (wall-server.js via cluster.js, 2 workers, port 4000)
     │
     ├── PostgreSQL (Docker container: wall-postgres)
     ├── Redis (localhost, rate limiting + session cache)
     └── Stripe (payment, SEPA/iDEAL flow)
```

**Current version:** v4.1.3  
**Runtime:** Node.js (cluster mode, 2 workers)  
**Server:** Hetzner Helsinki — `37.27.180.206`  
**App root:** `/opt/wall/`  
**Service name:** `paramant-wall` (systemd)

---

## Repository Structure

```
paramant-wall/
├── wall-server.js          # Main Express server — all routes, middleware, business logic
├── cluster.js              # Node.js cluster bootstrap (spawns 2 workers)
├── index.html              # Marketing/landing page + registration flow (single-file)
├── privacy.html            # Privacy policy page
├── config.html             # Customer dashboard / config interface
├── feed.html               # Tracker feed / activity viewer
├── recover.html            # Password / account recovery
├── success.html            # Post-payment success page (Stripe redirect)
├── cancel.html             # Post-payment cancel page (Stripe redirect)
├── snippet.js              # The Wall snippet — injected by website owners into their site
├── trackers.js             # Tracker definition database (what to block/replace)
├── SECURITY_RISK_MATRIX.md # Internal security audit and risk documentation
└── README.md               # This file
```

---

## Server Access

```bash
# SSH
ssh -i ~/.ssh/id_wall root@37.27.180.206

# App location
cd /opt/wall/

# Service management
systemctl status paramant-wall
systemctl restart paramant-wall
systemctl stop paramant-wall

# Live logs
journalctl -u paramant-wall -f

# Worker status (cluster)
node cluster.js   # only run manually for testing; use systemd in prod
```

---

## Database

### PostgreSQL
Runs in Docker as `wall-postgres`.

```bash
# Connect
docker exec -it wall-postgres psql -U wall -d wall

# Check container status
docker ps | grep wall-postgres
```

**Key tables:**

| Table | Purpose |
|-------|---------|
| `users` | Account credentials, email, deletion tracking |
| `customers` | Linked to users, holds `api_key`, `enabled` flag |
| `projects` | Per-customer proxy projects with `feed_hash` |
| `usage_monthly` | Aggregated request + blocked stats per month |
| `magic_links` | Passwordless login tokens with expiry |
| `pending_accounts` | Pre-payment registration state |
| `view_tokens` | Dashboard session tokens |
| `wall_configs` | Per-customer proxy configuration JSON |

### Redis
Runs on localhost. Used for rate limiting and session caching.

```bash
redis-cli ping   # should return PONG
redis-cli info   # full stats
```

---

## Environment Variables

These must be present in the runtime environment (systemd unit or `.env`):

```
DATABASE_URL          PostgreSQL connection string
REDIS_URL             Redis connection string (default: localhost)
STRIPE_SECRET_KEY     Stripe secret key (live)
STRIPE_WEBHOOK_SECRET Stripe webhook signing secret
POSTMARK_API_KEY      Transactional email (setup in progress)
SESSION_SECRET        Express session secret
DOMAIN                paramant.app
```

---

## Payment Flow (Stripe)

- Integration: Stripe Checkout with **SEPA Direct Debit / iDEAL**
- Flow: `index.html` → Stripe Checkout → `success.html` or `cancel.html`
- Webhooks handled in `wall-server.js` — verify signature before processing
- On successful payment: customer is activated (`customers.enabled = true`)

⚠️ **Known production bug:** `doRegister` function is not defined in the production `index.html`. Registration via the UI is currently broken. Fix is pending — do not deploy registration-dependent features until this is resolved.

---

## The Wall Snippet

`snippet.js` is the client-side script that website owners embed on their site:

```html
<script src="https://wall.paramant.app/snippet.js?key=API_KEY"></script>
```

- Identifies the customer via `api_key`
- Intercepts outbound requests matching patterns in `trackers.js`
- Proxies or drops requests based on customer `wall_config`
- Zero data retained — no visitor PII touches the WALL server

`trackers.js` contains the tracker pattern database — add new tracker definitions here when expanding coverage.

---

## Nginx Configuration

Nginx sits in front of Node.js:

```
HTTPS :443 → 127.0.0.1:4000
```

Config location on server: `/etc/nginx/sites-available/paramant-wall`

Cloudflare handles outer TLS. Nginx handles inner TLS (mTLS config in progress). Do not expose port 4000 directly — always route through Nginx.

---

## Deployment Workflow

There is no CI/CD pipeline yet. Deployments are manual:

```bash
# 1. Pull latest from local to server
scp -i ~/.ssh/id_wall index.html privacy.html wall-server.js \
  root@37.27.180.206:/opt/wall/

# 2. Restart service
ssh -i ~/.ssh/id_wall root@37.27.180.206 "systemctl restart paramant-wall"

# 3. Verify
ssh -i ~/.ssh/id_wall root@37.27.180.206 "journalctl -u paramant-wall -n 30"
```

**Backup convention:** Before any production edit, backup files to `/opt/wall/backup/` with timestamp suffix, e.g. `index-GOLDEN-20260327_0839.html`.

---

## Email

Transactional email is handled by **Postmark** (setup in progress — not yet live in production). Until Postmark is active, no automated emails are sent.

Inbound privacy requests: `privacy@paramant.app` (Cloudflare Email Routing → personal inbox).

---

## Security Notes

See `SECURITY_RISK_MATRIX.md` for the full internal audit.

Key points:
- All API keys are stored hashed in PostgreSQL
- `deleted_at` soft-delete pattern used on `users` table — always filter `WHERE deleted_at IS NULL`
- Rate limiting via Redis on all public endpoints
- Stripe webhook signatures must be verified before any state change
- mTLS between Cloudflare and Nginx: configuration hardening in progress

---

## Known Issues / Open TODOs

| Priority | Item |
|----------|------|
| 🔴 Critical | `doRegister` not defined in production HTML — registration broken |
| 🟠 High | Postmark SMTP setup not complete — no transactional email |
| 🟠 High | Cloudflare/Nginx/mTLS hardening not finalized |
| 🟡 Medium | No CI/CD pipeline — all deploys are manual SCP |
| 🟡 Medium | Backup folder on server accumulates — no automated cleanup |

---

## Contact

**Mick Beer — Founder, PARAMANT**  
privacy@paramant.app  
Harderwijk, The Netherlands
