# PARAMANT WALL — v4.0

> **Proprietary software. © 2026 PARAMANT.** Privacy proxy **+** first-party k-anonymous analytics.

Cookies stripped · IP **CSPRNG**-anonymised · PII blocked · **no metric backed by fewer than k people** · zero logging.

---

## What changed in v4.0

v4.0 keeps the entire SaaS shell from v3.x (Stripe SEPA/iDEAL checkout, magic-link
accounts, customer dashboard, live feed, GA4/Meta interception proxies, nginx +
systemd + Postgres + Redis) and drops in **paramant-core** — the anonymisation
engine that didn't exist when this project started.

| Area | v3.x | v4.0 |
|---|---|---|
| Visitor anonymisation | `sha256(ip + "wall-2026-4-30")` — **predictable salt, brute-forceable** | CSPRNG salt, RAM-only, rotates every UTC midnight — **unreconstructable** |
| IP handling | full IP hashed | coarsened to /24 (v4) or /48 (v6) **before** hashing |
| UA | family string | `{browser-family / os-family}`, version entropy dropped |
| Re-identification floor | none — a lone rare event could identify someone | **k-anonymity gate**: events held until >= k distinct visitors, sub-k buckets dropped |
| First-party analytics | none (proxy only) | **native RAM-only analytics** through the same k-anon gate |
| GA4 cid/client_id | hashed with the predictable salt | hashed with the core HMAC |
| /api/version | broken dead-code (unbalanced if(false)) | fixed, returns real version |

Nothing in the paying-customer flow changed. The motor underneath did.

---

## paramant-core (core/)

```
core/
  anonymizer.js   CSPRNG daily-rotating salt, /24 coarsening, PII + tracking-param scrub
  kanon.js        k-anonymity release gate (buffer until >= k, else drop)
  native.js       first-party RAM-only rolling aggregates (no disk, no event log)
  index.js        createCore() — wires the three together for wall-server.js
```

Each cluster worker holds its own RAM-only salt and buffers. Tokens only need to
be consistent within a request's lifetime; k-anon buckets aggregate per worker.

### Guarantees (proven in test/privacy.test.js)
- same visitor + same day => same token; different worker/day => different token
- /24 neighbours collapse to one token; IPv6-mapped IPv4 normalised
- salt rotation makes yesterday's tokens unreconstructable
- emails / phones / IDs scrubbed from strings, URLs and payloads; gclid/fbclid/... stripped
- k-anon gate buffers below k, flushes at k, drops sub-k buckets on sweep
- native adapter exposes aggregates only — never raw events

```bash
npm test   # 9/9
```

---

## New endpoints

| Route | Purpose |
|---|---|
| POST /collect | Cookieless first-party beacon. Strips cookies/IP/PII, tokenises, k-anon gate, native store. Returns 204, never Set-Cookie. |
| GET /api/native/state | Aggregate report + core diagnostics (salt fingerprint, k-anon buffer state). Aggregates only. |
| GET /health | Now includes live core state. |

The snippet (public/snippet.js v4.0) still intercepts outbound GA4/Meta trackers
**and** now fires a cookieless first-party pageview to /collect. Custom events:

```js
window.wall('signup', { plan: 'pro' });   // props PII-scrubbed server-side
```

---

## Run

```bash
npm install
# required env: DATABASE_URL, STRIPE_SECRET_KEY, SESSION_SECRET  (optional: REDIS_URL, WALL_K)
WALL_K=5 npm start          # cluster mode (cluster.js -> 2 workers)
node wall-server.js         # single process, for dev
```

Architecture unchanged from v3.x:

```
browser -> Cloudflare (TLS/WAF) -> Nginx :443 -> Node cluster :4000
                                                   |-- PostgreSQL (accounts, billing)
                                                   |-- Redis (rate limit, feed)
                                                   \-- Stripe (SEPA/iDEAL)
```

Server: Hetzner. Service paramant-wall (systemd). App root /opt/wall/.
Static assets now live in public/ (the server already sendFiles from there).

---

## Deploy (unchanged manual flow)

```bash
scp -r core public wall-server.js trackers.js cluster.js \
  root@<server>:/opt/wall/
ssh root@<server> "cd /opt/wall && npm install --omit=dev && systemctl restart paramant-wall"
ssh root@<server> "journalctl -u paramant-wall -n 30"
```

Behind Cloudflare (orange cloud), Wall reads CF-IPCountry for coarse geo — the
process itself never geolocates an IP.

---

## Contact
**Mick Beer — PARAMANT** · privacy@paramant.app · Harderwijk, NL
