
╔══════════════════════════════════════════════════════════════════════════╗
║         PARAMANT WALL — RISICO MATRIX & FEARED EVENTS ANALYSE          ║
║                          v3.4.0 · 2026-03-27                           ║
╚══════════════════════════════════════════════════════════════════════════╝

┌─────────────────────────────────────────────────────────────────────────┐
│ FEARED EVENT 1: SERVER VOLLEDIG GECOMPROMITTEERD (root access)          │
├─────────────┬──────────────────────────────────────────────────────────┤
│ Kans        │ Laag-Middel (VPS, goed gehardend)                        │
│ Impact      │ KRITIEK                                                   │
│ Wat lekt    │ API keys (plaintext in DB), email adressen, Stripe keys   │
│ Wat NIET    │ IP-adressen (nooit opgeslagen), request payloads (zero log│
│             │ wachtwoorden (passwordless), betaalgegevens (Stripe)      │
├─────────────┴──────────────────────────────────────────────────────────┤
│ HUIDIGE MITIGATIES:                                                     │
│  ✓ PostgreSQL alleen op localhost (niet extern bereikbaar)              │
│  ✓ Redis alleen op loopback                                             │
│  ✓ Nginx access_log off (geen IP logs op disk)                         │
│  ✓ Passwordless systeem (geen wachtwoorddatabase)                       │
│  ✓ Betaalgegevens bij Stripe (niet op onze server)                     │
│  ✗ API keys in plaintext in DB → ACTIE: toevoegen key_hash only        │
│  ✗ Geen file integrity monitoring (FIM)                                 │
│  ✗ Geen immutable infrastructure (server kan gewijzigd worden)         │
│                                                                         │
│ AANBEVOLEN MAATREGELEN:                                                 │
│  1. API keys hashen in DB — alleen key_hash opslaan, nooit plaintext   │
│  2. Fail2ban op SSH + alleen key auth (al zo?)                         │
│  3. Automatische DB encryptie at rest (Hetzner volume encryption)      │
│  4. Daily encrypted backup naar off-site (S3/Backblaze)                │
│  5. Tripwire/AIDE file integrity monitoring                             │
│  6. Intrusion Detection: auditd + ossec                                 │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│ FEARED EVENT 2: API KEY GESTOLEN (via client-side aanval)               │
├─────────────┬──────────────────────────────────────────────────────────┤
│ Kans        │ Middel (key zit in snippet.js in browser, zichtbaar)     │
│ Impact      │ Middel (misbruik proxy, kosten, spam requests)            │
│ Wat lekt    │ API key → proxy misbruik voor ander domein               │
│ Wat NIET    │ Email, account data (key ≠ account toegang)              │
├─────────────┴──────────────────────────────────────────────────────────┤
│ HUIDIGE MITIGATIES:                                                     │
│  ✓ Domain lock: key werkt ALLEEN op geregistreerd domein               │
│  ✓ Rate limiting op proxy endpoints                                     │
│  ✓ Key revocation via revokeKey()                                      │
│  ✗ Geen automatische anomaly detection (spike in requests)             │
│  ✗ Geen per-key request budget enforcement                              │
│                                                                         │
│ AANBEVOLEN MAATREGELEN:                                                 │
│  1. Anomaly alert: >10x normaal volume → email + auto-suspend          │
│  2. Per-key hard budget (plan limiet afdwingen in proxy)               │
│  3. Key rotation: maandelijkse herinnering om key te roteren           │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│ FEARED EVENT 3: STRIPE WEBHOOK AANVAL (replay / spoofing)               │
├─────────────┬──────────────────────────────────────────────────────────┤
│ Kans        │ Laag (HMAC-SHA256 verificatie aanwezig)                  │
│ Impact      │ Hoog (gratis accounts aanmaken)                           │
│ Wat lekt    │ Gratis API keys, DB vervuiling                           │
├─────────────┴──────────────────────────────────────────────────────────┤
│ HUIDIGE MITIGATIES:                                                     │
│  ✓ Stripe webhook signature verificatie (constructEvent)               │
│  ✓ Idempotency check (email al actief → skip)                         │
│  ✗ Geen webhook replay window check (Stripe: 300 sec TTL)             │
│                                                                         │
│ AANBEVOLEN MAATREGELEN:                                                 │
│  1. Controleer event.created timestamp — reject als > 5 min oud       │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│ FEARED EVENT 4: HETZNER DATACENTER OUTAGE / SERVER DOWN                 │
├─────────────┬──────────────────────────────────────────────────────────┤
│ Kans        │ Laag (Hetzner 99.9% SLA)                                 │
│ Impact      │ Hoog (alle klanten zijn offline, snippet.js faalt)       │
│ Wat lekt    │ Niets — Wall doet niets als hij down is                  │
├─────────────┴──────────────────────────────────────────────────────────┤
│ SNIPPET GEDRAG BIJ WALL DOWN:                                           │
│  v3.4.0: Offline queue (max 20 requests, max 5 min TTL)               │
│  Requests worden gequeued en flushed bij reconnect                     │
│  Tracking requests gaan NIET door naar Google/Meta bij Wall down       │
│  → Privacy blijft gegarandeerd, analytics valt wel weg                │
│                                                                         │
│ AANBEVOLEN MAATREGELEN:                                                 │
│  1. Monitoring: UptimeRobot / BetterStack op /health                  │
│  2. Standby VPS (Hetzner snapshot → snel restore)                     │
│  3. Cloudflare als fallback CDN + caching van snippet.js              │
│  4. StatusPage voor klanten                                            │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│ FEARED EVENT 5: SNIPPET.JS CDN AANVAL / XSS VIA SNIPPET                │
├─────────────┬──────────────────────────────────────────────────────────┤
│ Kans        │ Laag-Middel (snippet wordt van wall.paramant.app geservd)│
│ Impact      │ KRITIEK (snippet draait op ALLE klantwebsites)           │
│ Wat kan     │ Kwaadaardige code injecteren op alle klantwebsites       │
├─────────────┴──────────────────────────────────────────────────────────┤
│ HUIDIGE MITIGATIES:                                                     │
│  ✓ Snippet geserverd van eigen server (geen derde CDN)                │
│  ✓ Cache-Control: max-age=300 (5 min — snel te updaten)              │
│  ✓ Geen externe dependencies in snippet.js                            │
│  ✗ Geen Subresource Integrity (SRI) hash in klant-implementatie       │
│  ✗ Geen snippet versie-pinning                                        │
│                                                                         │
│ AANBEVOLEN MAATREGELEN:                                                 │
│  1. Publiceer SHA-256 hash van snippet.js bij elke release            │
│  2. Klanten kunnen SRI gebruiken: integrity="sha256-..."              │
│  3. Strict CSP op wall.paramant.app zelf                              │
│  4. Cloudflare WAF op de snippet endpoint                             │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│ FEARED EVENT 6: DATABASE DUMP GESTOLEN                                   │
├─────────────┬──────────────────────────────────────────────────────────┤
│ Kans        │ Laag (PostgreSQL loopback only)                           │
│ Impact      │ Middel (emails + API keys zichtbaar)                     │
│ Wat NIET    │ IP-adressen, payloads, wachtwoorden, betaaldata          │
├─────────────┴──────────────────────────────────────────────────────────┤
│ AANBEVOLEN MAATREGELEN:                                                 │
│  1. pg_dump versleuteld naar off-site (dagelijks)                     │
│  2. Email adressen hashen in DB (alleen nodig voor recovery)          │
│  3. API keys: alleen key_hash opslaan + salt                          │
└─────────────────────────────────────────────────────────────────────────┘

╔══════════════════════════════════════════════════════════════════════════╗
║  SNIPPET.JS v3.4.0 — LIMIETEN & PERFECTIE ANALYSE                      ║
╚══════════════════════════════════════════════════════════════════════════╝

STERKTES (wat het nu goed doet):
  ✓ fetch, XHR, sendBeacon volledig onderschept
  ✓ MutationObserver blokkeert dynamisch geladen scripts
  ✓ 45+ tracker patronen
  ✓ 35+ tracking cookie prefixes geblokkeerd
  ✓ Tracking pixels (1x1 img) onderschept
  ✓ Offline queue met retry + backoff
  ✓ window.gtag / dataLayer sink
  ✓ wall:ready / wall:blocked / wall:cookie-blocked events
  ✓ Geen URL lekkage naar Wall server
  ✓ Geen logs in productie
  ✓ Validatie van key formaat (wk_ + 48 hex chars)
  ✓ credentials: omit (nooit cookies meesturen naar Wall)
  ✓ Tracking headers geblokkeerd in XHR (referer, x-forwarded-for)

LIMIETEN (eerlijk):
  ✗ Service Workers: requests vanuit SW worden NIET onderschept
  ✗ WebSockets: tracking via WS is niet geblokkeerd
  ✗ Shadow DOM: scripts in shadow roots kunnen ontsnappen
  ✗ iframes van eigen domein: cross-origin iframes zijn buiten bereik
  ✗ CSS tracking (bijv. font requests): niet geblokkeerd
  ✗ Browser extensions kunnen snippet omzeilen
  ✗ Server-side tracking (GA4 Measurement Protocol direct): onmogelijk te blokkeren client-side

PERFECTIE ROADMAP:
  v3.5.0: ServiceWorker versie voor offline-first + SW-level interceptie
  v3.6.0: WebSocket proxy endpoint + interceptie
  v3.7.0: SRI hash publicatie + versie-pinning voor klanten
  v3.8.0: Automatische patronen update via /api/patterns (gesigneerd)

