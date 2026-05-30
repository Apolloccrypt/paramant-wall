# Changelog

## v4.0.0 — paramant-core integration

The original v3.x was a working privacy-proxy SaaS, but its anonymisation was
weak (predictable daily salt). v4.0 replaces the motor without disturbing the
business shell.

### Added
- `core/` — paramant-core engine:
  - `anonymizer.js`: CSPRNG salt (RAM-only, rotates UTC midnight), /24 + /48 IP
    coarsening, UA family reduction, PII + tracking-param scrubbing.
  - `kanon.js`: k-anonymity release gate. Events buffered until a quasi-identifier
    bucket holds >= k distinct visitors; sub-k buckets dropped, never forwarded.
  - `native.js`: first-party RAM-only rolling aggregates (no disk, no event log).
  - `index.js`: `createCore()` wiring.
- `POST /collect` — cookieless first-party analytics beacon.
- `GET /api/native/state` — aggregate report + core diagnostics.
- `window.wall(name, props)` custom-event API in the snippet.
- `test/privacy.test.js` — 9 tests proving the privacy guarantees.

### Changed
- `anonymizeIP` / `anonymizeUA` / `dailySalt` now backed by paramant-core
  (previously `sha256(ip + "wall-YYYY-M-D")`, which was brute-forceable).
- GA4 proxy `cid`/`client_id` now hashed with the core HMAC.
- `GET /health` includes live core state.
- Static assets moved to `public/` (matches existing `sendFile` paths).
- Server + snippet version -> 4.0.0.

### Fixed
- `GET /api/version` had unbalanced dead-code (`if (false) {` never closed),
  which was a hard syntax error. Replaced with a clean working route.

## v4.1.0 — NL tracker coverage (Piwik PRO + Adobe + more)

Hard requirement: Wall must sit as an anonymising filter in front of every
tracker used in NL — especially Piwik PRO (Logius / government) and Adobe
Analytics — not just GA4/Meta.

### Added
- `trackers.js`: Piwik PRO, Matomo, Adobe Analytics, Adobe Target, Snowplow,
  Tealium, Contentsquare, NL B2B (Leadinfo/Snitcher). Now 56 trackers.
  NL-critical analytics default to `strip` (anonymise + forward) not `block`,
  so customers keep working analytics.
- `core/strip.js`: testable vendor strip engine. Stable identifiers
  (`_id`/`vid`/`aid`/`cid`...) → daily-rotating token; PII / IP / `token_auth`
  → dropped. Works on both URL params and JSON/text bodies.
- `/proxy/piwik` and `/proxy/adobe`: dedicated strip-proxies that anonymise the
  vendor-specific PII fields, forward to the real collector with X-Forwarded-For
  neutralised, and also feed the first-party k-anon store.
- snippet v4.1.0: intercepts Piwik PRO / Adobe / Matomo / Snowplow / Tealium
  collect calls and routes each to the right strip-proxy via `?_orig=`.

### Tests
- 13/13 pass, incl. Piwik PRO `token_auth`+`cip`+`uid` stripped, Adobe
  `c_ip`+`email`+`vid` stripped, and "all NL-critical trackers strip" assertion.

## v4.2.0 — Cryptographic attestation + verification extension

Goal: let anyone independently PROVE a site uses Paramant Wall — for sales demos
and for end-user trust — without trusting the site's own claims.

### Added (server)
- `core/attest.js`: Ed25519 attestation. Server holds a private key (env
  WALL_ATTEST_PRIVKEY or /opt/wall/.attest_key.pem, auto-generated + persisted
  on first run). Signs domain+timestamp+version+nonce with a short TTL.
- `GET /.well-known/paramant-wall?domain=<d>`: signed attestation, but only for
  domains with an ENABLED customer (fails closed to enrolled:false).
- `GET /.well-known/paramant-wall-key`: the public key to embed/pin in the extension.

### Added (separate: wall-verify-extension/)
- Manifest V3 browser extension. Independently observes the page's network
  requests, flags trackers as DIRECT (leaking) vs ROUTED (through Wall), and
  verifies Wall's Ed25519 signature against the embedded/pinned public key.
- Verdict badge: green=protected, amber=partial, red=unprotected, grey=clean.

### Tests
- 16/16 pass, incl. attestation signs+verifies, tampered domain rejected
  (unforgeable), public key is raw32.
