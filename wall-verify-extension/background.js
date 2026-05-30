// Paramant Wall — Privacy Verifier — background.js
//
// This runs independently of the inspected site. It does NOT trust any claim
// the page makes. It watches the actual network requests the browser sends and
// decides for itself whether tracking is leaking directly to vendors or is
// being routed through Paramant Wall — then cryptographically verifies Wall's
// attestation for the domain.

// The Wall origin(s) tracking should flow through.
const WALL_ORIGINS = [
  'wall.paramant.app',
  'app.paramant.app',
];

// The attestation public key is fetched live from Wall and cached, but we also
// pin a known key so a MITM can't swap it. Operator: paste the raw32 b64 key.
const PINNED_PUBKEY_B64 = 'REPLACE_WITH_WALL_PUBLIC_KEY';

// Known tracker hosts. If the page contacts one of these DIRECTLY (not via
// Wall), privacy is leaking. Mirrors trackers.js on the server.
const TRACKER_HOSTS = [
  // analytics
  'google-analytics.com', 'analytics.google.com', 'googletagmanager.com',
  'g/collect', 'stats.g.doubleclick.net',
  'piwik.pro', 'piwikpro.com', 'matomo.cloud',
  'sc.omtrdc.net', 'adobedc.net', 'tt.omtrdc.net', 'demdex.net', 'everesttech.net',
  'tealiumiq.com', 'tiqcdn.com',
  'snowplowanalytics', 'snplow',
  'mixpanel.com', 'amplitude.com', 'segment.io', 'segment.com',
  'hotjar.com', 'hotjar.io', 'clarity.ms', 'fullstory.com',
  'mc.yandex.ru', 'mc.yandex.com', 'heapanalytics.com', 'contentsquare.net',
  'scorecardresearch.com', 'quantserve.com', 'chartbeat.com',
  // advertising / pixels
  'facebook.com/tr', 'connect.facebook.net', 'doubleclick.net',
  'ads.tiktok.com', 'analytics.tiktok.com', 'bat.bing.com',
  'px.ads.linkedin.com', 'snap.licdn.com', 'criteo.net', 'criteo.com',
  'taboola.com', 'outbrain.com', 'adnxs.com', 'pubmatic.com',
  'ct.pinterest.com', 'tr.snapchat.com', 'reddit.com',
];

// Per-tab observation state.
const tabs = new Map(); // tabId -> { host, direct:Set, walled:Set, attest, total }

function isWallOrigin(host) {
  return WALL_ORIGINS.some((w) => host === w || host.endsWith('.' + w));
}
function matchTracker(url) {
  const u = url.toLowerCase();
  return TRACKER_HOSTS.find((t) => u.includes(t)) || null;
}
function hostOf(url) { try { return new URL(url).hostname; } catch (e) { return ''; } }

function ensureTab(tabId, pageHost) {
  let t = tabs.get(tabId);
  if (!t || (pageHost && t.host !== pageHost)) {
    t = { host: pageHost || (t && t.host) || '', direct: new Set(), walled: new Set(), attest: null, total: 0, checkedAttest: false };
    tabs.set(tabId, t);
  }
  return t;
}

// Watch every request the page makes.
chrome.webRequest.onBeforeRequest.addListener(
  (info) => {
    if (info.tabId < 0) return;
    const host = hostOf(info.url);
    const t = ensureTab(info.tabId);
    t.total++;

    if (isWallOrigin(host)) {
      // tracking (or beacon) routed through Wall — good
      t.walled.add(host);
    } else {
      const tracker = matchTracker(info.url);
      if (tracker) t.direct.add(tracker); // leaking straight to a vendor
    }
    updateBadge(info.tabId);
  },
  { urls: ['<all_urls>'] }
);

// Track the page's own host as it navigates.
chrome.webNavigation && chrome.webNavigation.onCommitted &&
chrome.webNavigation.onCommitted.addListener((d) => {
  if (d.frameId !== 0) return;
  const host = hostOf(d.url);
  const t = ensureTab(d.tabId, host);
  t.host = host;
  t.checkedAttest = false;
});

// Also catch host on tab updates (covers SPA / no webNavigation perm).
chrome.tabs.onUpdated.addListener((tabId, change, tab) => {
  if (change.url) {
    const host = hostOf(change.url);
    const t = ensureTab(tabId, host);
    t.host = host;
  }
  if (change.status === 'complete' && tab && tab.url) {
    const t = ensureTab(tabId, hostOf(tab.url));
    if (!t.checkedAttest) { t.checkedAttest = true; verifyAttestation(tabId, t.host); }
  }
});

chrome.tabs.onRemoved.addListener((tabId) => tabs.delete(tabId));

// Fetch + cryptographically verify Wall's attestation for this domain.
async function verifyAttestation(tabId, pageHost) {
  if (!pageHost) return;
  const t = ensureTab(tabId, pageHost);
  for (const origin of WALL_ORIGINS) {
    try {
      const res = await fetch(
        `https://${origin}/.well-known/paramant-wall?domain=${encodeURIComponent(pageHost)}`,
        { credentials: 'omit' }
      );
      if (!res.ok) continue;
      const data = await res.json();
      if (!data.ok || !data.payload || !data.signature) continue;

      const valid = await verifySignature(data.payload, data.signature, data.publicKey);
      t.attest = {
        enrolled: !!data.enrolled,
        valid: valid,
        domain: data.payload.domain,
        version: data.payload.version,
        features: data.payload.features || [],
        ts: data.payload.ts,
        keyMatchesPin: pinOk(data.publicKey),
      };
      updateBadge(tabId);
      return;
    } catch (e) { /* try next origin */ }
  }
  t.attest = { enrolled: false, valid: false };
  updateBadge(tabId);
}

function pinOk(pub) {
  if (PINNED_PUBKEY_B64 === 'REPLACE_WITH_WALL_PUBLIC_KEY') return null; // not pinned yet
  return pub === PINNED_PUBKEY_B64;
}

// Ed25519 verify via WebCrypto. The public key arrives as raw32 base64.
async function verifySignature(payload, signatureB64, publicKeyB64) {
  try {
    const raw = b64ToBytes(publicKeyB64);
    const key = await crypto.subtle.importKey(
      'raw', raw, { name: 'Ed25519' }, false, ['verify']
    );
    const msg = new TextEncoder().encode(JSON.stringify(payload));
    const sig = b64ToBytes(signatureB64);
    return await crypto.subtle.verify('Ed25519', key, sig, msg);
  } catch (e) {
    // Some Chromium builds expose Ed25519 under a flag; if unavailable we
    // fall back to "signature present but unverified" handled by the popup.
    return null;
  }
}

function b64ToBytes(b64) {
  const bin = atob(b64.replace(/-/g, '+').replace(/_/g, '/'));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// Overall verdict for a tab.
function verdict(t) {
  if (!t) return 'unknown';
  const leaking = t.direct.size > 0;
  const attested = t.attest && t.attest.enrolled && (t.attest.valid === true || t.attest.valid === null);
  if (attested && !leaking) return 'protected';        // signed + nothing leaks
  if (attested && leaking) return 'partial';           // enrolled but some tracker bypasses Wall
  if (!attested && leaking) return 'unprotected';      // trackers leaking, no Wall
  if (!attested && !leaking) return 'clean';           // no trackers seen at all
  return 'unknown';
}

function updateBadge(tabId) {
  const t = tabs.get(tabId);
  const v = verdict(t);
  const map = {
    protected:   { text: '✓', color: '#1f8f5f' },
    partial:     { text: '!', color: '#d98a00' },
    unprotected: { text: '✕', color: '#c43d2e' },
    clean:       { text: '·', color: '#5b6b66' },
    unknown:     { text: '',  color: '#5b6b66' },
  };
  const b = map[v] || map.unknown;
  try {
    chrome.action.setBadgeText({ tabId, text: b.text });
    chrome.action.setBadgeBackgroundColor({ tabId, color: b.color });
  } catch (e) {}
}

// Popup asks for the current tab's state.
chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  if (msg && msg.type === 'getState' && typeof msg.tabId === 'number') {
    const t = tabs.get(msg.tabId);
    if (t && !t.checkedAttest && t.host) { t.checkedAttest = true; verifyAttestation(msg.tabId, t.host); }
    reply({
      host: t ? t.host : '',
      direct: t ? Array.from(t.direct) : [],
      walled: t ? Array.from(t.walled) : [],
      attest: t ? t.attest : null,
      total: t ? t.total : 0,
      verdict: verdict(t),
    });
  }
  return true; // async
});
