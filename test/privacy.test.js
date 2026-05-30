'use strict';
const assert = require('node:assert');
const { test } = require('node:test');
const { Anonymizer } = require('../core/anonymizer');
const { KAnonGate } = require('../core/kanon');
const { NativeAdapter } = require('../core/native');

test('same visitor same day => same token', () => {
  const a = new Anonymizer();
  const id = { ip: '81.83.12.44', ua: 'Mozilla/5.0 Firefox/120', origin: 'shop.nl' };
  assert.equal(a.visitorToken(id), a.visitorToken(id));
});

test('legacy salt was predictable; new salt is CSPRNG (two instances differ)', () => {
  const a = new Anonymizer();
  const b = new Anonymizer();
  const id = { ip: '81.83.12.44', ua: 'x', origin: 's' };
  // Different processes/workers get independent random salts => different tokens.
  assert.notEqual(a.visitorToken(id), b.visitorToken(id));
});

test('same /24, different last octet => SAME token (coarsened)', () => {
  const a = new Anonymizer();
  assert.equal(
    a.visitorToken({ ip: '81.83.12.1', ua: 'x', origin: 's' }),
    a.visitorToken({ ip: '81.83.12.254', ua: 'x', origin: 's' })
  );
});

test('IPv6-mapped IPv4 is normalised', () => {
  const a = new Anonymizer();
  assert.equal(
    a.visitorToken({ ip: '::ffff:81.83.12.5', ua: 'x', origin: 's' }),
    a.visitorToken({ ip: '81.83.12.9', ua: 'x', origin: 's' })
  );
});

test('salt rotation makes yesterday tokens unreconstructable', () => {
  const a = new Anonymizer();
  const id = { ip: '81.83.12.44', ua: 'x', origin: 's' };
  const before = a.visitorToken(id);
  a._rotate();
  assert.notEqual(before, a.visitorToken(id));
});

test('PII scrubbed from strings, URLs, payloads', () => {
  const a = new Anonymizer();
  assert.ok(!a.scrubString('mail jan@example.com tel +31 6 12345678').includes('jan@example.com'));
  const u = a.scrubUrl('https://shop.nl/p?id=9&gclid=abc&fbclid=xyz&fbp=1');
  assert.ok(u.includes('id=9') && !u.includes('gclid') && !u.includes('fbclid') && !u.includes('fbp'));
  const p = a.scrubPayload({ email: 'x@y.com', em: 'h', plan: 'pro' });
  assert.equal(p.email, '[redacted]'); assert.equal(p.em, '[redacted]'); assert.equal(p.plan, 'pro');
});

test('k-anon gate buffers below k, flushes at k', () => {
  const flushed = [];
  const gate = new KAnonGate({ k: 3, onFlush: (e) => flushed.push.apply(flushed, e) });
  const base = { ts: Date.now(), event: 'pageview', path: '/x', country: 'NL', device: 'desktop' };
  gate.ingest(Object.assign({}, base, { visitor: 'a' }));
  gate.ingest(Object.assign({}, base, { visitor: 'b' }));
  assert.equal(flushed.length, 0);
  gate.ingest(Object.assign({}, base, { visitor: 'c' }));
  assert.equal(flushed.length, 3);
  gate.stop();
});

test('k-anon gate drops sub-k buckets (no singleton leaks)', () => {
  const flushed = [];
  const gate = new KAnonGate({ k: 5, ttlMs: 1, onFlush: (e) => flushed.push.apply(flushed, e) });
  gate.ingest({ ts: Date.now(), visitor: 'lonely', event: 'pageview', path: '/rare', country: 'IS', device: 'desktop' });
  return new Promise((r) => setTimeout(() => {
    gate._sweep();
    assert.equal(flushed.length, 0);
    gate.stop(); r();
  }, 10));
});

test('native adapter reports aggregates only', () => {
  const n = new NativeAdapter();
  const ts = Date.now();
  n.send([
    { ts, visitor: 'a', event: 'pageview', path: '/', country: 'NL', device: 'desktop', referrer: '' },
    { ts, visitor: 'b', event: 'pageview', path: '/', country: 'NL', device: 'mobile', referrer: 'https://google.com/x' },
  ]);
  const rep = n.report(new Date(ts).toISOString().slice(0, 10));
  assert.equal(rep.pageviews, 2);
  assert.equal(rep.uniqueVisitors, 2);
});

// ── Vendor strip engine (Piwik PRO + Adobe) ────────────────────────
const { stripTrackerUrl, stripTrackerBody } = require('../core/strip');
const { BUILT_IN_TRACKERS } = require('../trackers');

test('Piwik PRO: visitor _id pseudonymised, token_auth + cip dropped', () => {
  const a = new Anonymizer();
  const tok = a.visitorToken({ ip: '81.83.12.5', ua: 'x', origin: 'logius.nl' });
  const fields = BUILT_IN_TRACKERS.piwik_pro.stripFields;
  const url = 'https://logius.piwik.pro/ppms.php?idsite=5&rec=1&_id=abc123def456&uid=jan.jansen&cip=81.83.12.5&token_auth=SECRET&e_c=download&url=https://logius.nl/aanvraag';
  const out = stripTrackerUrl(a, url, fields, tok);
  assert.ok(out.includes('idsite=5'), 'keeps non-PII site id');
  assert.ok(out.indexOf('token_auth') === -1, 'drops token_auth');
  assert.ok(out.indexOf('cip=81.83.12.5') === -1, 'drops raw client IP');
  assert.ok(out.indexOf('jan.jansen') === -1, 'drops uid PII');
  assert.ok(out.indexOf(tok) !== -1, '_id replaced by daily token');
  assert.ok(out.indexOf('abc123def456') === -1, 'original _id gone');
});

test('Adobe Analytics: vid/aid pseudonymised, c_ip + email dropped', () => {
  const a = new Anonymizer();
  const tok = a.visitorToken({ ip: '145.7.1.9', ua: 'x', origin: 'rijksoverheid.nl' });
  const fields = BUILT_IN_TRACKERS.adobe_analytics.stripFields;
  const url = 'https://tenant.sc.omtrdc.net/b/ss/rsid/1/JS-2.22.0/s9999?vid=AAABBBCCC&aid=12345&mid=678&c_ip=145.7.1.9&email=burger@example.nl&eVar5=ingelogd&pe=lnk_o';
  const out = stripTrackerUrl(a, url, fields, tok);
  assert.ok(out.indexOf('c_ip=145.7.1.9') === -1, 'drops Adobe client IP');
  assert.ok(out.indexOf('burger@example.nl') === -1, 'drops email');
  assert.ok(out.indexOf('AAABBBCCC') === -1, 'original vid gone');
  assert.ok(out.indexOf(tok) !== -1, 'vid replaced by daily token');
});

test('strip body removes PII keys from JSON payloads', () => {
  const a = new Anonymizer();
  const body = JSON.stringify({ events: [{ data: { user_id: 42, email: 'x@y.nl', page: '/p' } }] });
  const out = stripTrackerBody(a, body, [], 'tok');
  assert.ok(out.indexOf('x@y.nl') === -1);
  assert.ok(out.indexOf('"user_id":42') === -1);
  assert.ok(out.indexOf('/p') !== -1);
});

test('all NL-critical trackers default to strip (not block) so analytics survives', () => {
  for (const k of ['piwik_pro', 'matomo', 'adobe_analytics', 'adobe_target', 'snowplow', 'tealium']) {
    assert.equal(BUILT_IN_TRACKERS[k].defaultAction, 'strip', k + ' must strip');
  }
});

// ── Attestation (verification extension) ───────────────────────────
const { Attestor } = require('../core/attest');

test('attestation signs and verifies for the right domain', () => {
  const a = new Attestor();
  const att = a.attest('logius.nl', { version: '4.1.0' });
  assert.ok(att.signature && att.publicKey);
  assert.equal(a.verify(att.payload, att.signature), true);
});

test('attestation rejects a tampered domain (unforgeable)', () => {
  const a = new Attestor();
  const att = a.attest('logius.nl', { version: '4.1.0' });
  const tampered = Object.assign({}, att.payload, { domain: 'evil.example' });
  assert.equal(a.verify(tampered, att.signature), false);
});

test('attestation public key is raw32 base64', () => {
  const a = new Attestor();
  const raw = Buffer.from(a.publicKeyB64, 'base64');
  assert.equal(raw.length, 32);
});
