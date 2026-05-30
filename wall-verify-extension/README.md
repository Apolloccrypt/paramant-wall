# Paramant Wall — Privacy Verifier (browser extension)

A browser extension that **independently** verifies whether the site you're on
routes its tracking through Paramant Wall — cookieless, IP-anonymised, PII-stripped.

It does **not** trust the site. It inspects the network requests your browser
actually sends, and verifies Wall's Ed25519 signature for the domain. A site
cannot fake the green checkmark.

## What it shows

The toolbar badge gives an at-a-glance verdict:

| Badge | Meaning |
|---|---|
| **✓** green | Protected — domain is enrolled, signature verified, no tracker leaks |
| **!** amber | Partly protected — enrolled, but some tracker bypasses Wall |
| **✕** red | Not protected — trackers reaching Google/Adobe/Piwik directly |
| **·** grey | No known trackers seen on this page |

The popup shows the evidence: the cryptographic attestation (enrolled? signature
valid? key matches pin? Wall version, when attested) and the actual tracker
requests observed, each tagged **DIRECT** (leaking) or **ROUTED** (through Wall).

## How verification works

1. **Observation** — the background worker watches every request the page makes.
   Requests to known tracker hosts (Google Analytics, Adobe `sc.omtrdc.net`,
   Piwik PRO, Matomo, Meta, etc.) are flagged DIRECT if they don't go through
   Wall, or ROUTED if they do.
2. **Attestation** — the extension fetches
   `https://wall.paramant.app/.well-known/paramant-wall?domain=<site>` and
   verifies the returned Ed25519 signature against the public key. Only domains
   with an active Wall customer get a positive attestation, and the signature is
   bound to the domain + a short TTL, so it can't be replayed elsewhere.

## Install (developer / unpacked)

1. Open `chrome://extensions` (or `edge://extensions`).
2. Enable **Developer mode**.
3. **Load unpacked** → select this `wall-verify-extension/` folder.
4. Pin the extension and open any site to see the verdict.

## One required config step — pin the public key

For full protection against a man-in-the-middle swapping the attestation key,
pin Wall's public key in the extension:

1. Get the key:
   ```
   curl -s https://wall.paramant.app/.well-known/paramant-wall-key
   ```
   (or read it from the server log line `[attest] PUT THIS PUBLIC KEY...`)
2. In `background.js`, replace:
   ```js
   const PINNED_PUBKEY_B64 = 'REPLACE_WITH_WALL_PUBLIC_KEY';
   ```
   with the `publicKey` value.
3. Reload the extension.

Until pinned, the extension still verifies the signature live; pinning just
removes trust in the key-distribution channel.

## Notes

- Ed25519 in-page verification needs a recent Chromium (Chrome/Edge 113+ with
  WebCrypto Ed25519). On older builds the popup shows the signature as
  "present but unverified" and falls back to the enrollment check.
- The extension needs `webRequest` + host permissions to observe traffic; it
  stores nothing and sends nothing anywhere except the attestation fetch to Wall.
- Add new Wall origins (e.g. `app.paramant.app`) to `WALL_ORIGINS` in
  `background.js` if you serve Wall on more hosts.
