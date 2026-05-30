/**
 * PARAMANT CORE — anonymizer
 *
 * Replaces the legacy dailySalt()/anonymizeIP() which used a PREDICTABLE salt
 * (the literal string "wall-2026-4-30"). That was brute-forceable: anyone who
 * knew the date could hash every candidate IP until a token matched, fully
 * de-anonymising the data.
 *
 * This core fixes that. The salt is 32 CSPRNG bytes, lives ONLY in RAM, and
 * rotates every UTC midnight. Once a day ends, that day's tokens cannot be
 * reconstructed — not by an attacker, not by us, not under subpoena.
 *
 * Defence in depth before hashing:
 *   - IP coarsened to /24 (v4) or /48 (v6) so neighbours collapse together
 *   - UA reduced to {browser-family / os-family}, dropping version entropy
 */
'use strict';
const crypto = require('crypto');

const ROTATION_MS = 24 * 60 * 60 * 1000;

const PII_PATTERNS = [
  { re: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, tag: '[email]' },
  { re: /\+?\d[\d\s().-]{7,}\d/g, tag: '[phone]' },
  { re: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, tag: '[ip]' },
  { re: /\b(?:[A-Fa-f0-9]{1,4}:){2,}[A-Fa-f0-9]{0,4}\b/g, tag: '[ip6]' },
  { re: /\b\d{13,19}\b/g, tag: '[num]' },
  { re: /\b\d{9}\b/g, tag: '[id]' },
];

const TRACKING_PARAMS = new Set([
  'gclid','fbclid','msclkid','dclid','twclid','ttclid','yclid','utm_id',
  '_ga','_gl','mc_eid','mc_cid','igshid','vero_id','wickedid','oly_anon_id',
  'oly_enc_id','s_kwcid','ef_id','cmpid','external_id','fbp','fbc',
]);

class Anonymizer {
  constructor(opts) {
    opts = opts || {};
    this.rotationMs = opts.rotationMs || ROTATION_MS;
    this._salt = null;
    this._saltEpoch = 0;
    this._rotate();
  }
  _rotate() {
    this._salt = crypto.randomBytes(32);
    this._saltEpoch = this._epoch();
  }
  _epoch() { return Math.floor(Date.now() / this.rotationMs); }
  _ensureFresh() { if (this._epoch() !== this._saltEpoch) this._rotate(); }

  coarsenIp(ip) {
    if (!ip) return '0';
    ip = String(ip).trim();
    // strip IPv6-mapped IPv4 prefix
    ip = ip.replace(/^::ffff:/i, '');
    if (ip.indexOf(':') >= 0) {
      return ip.split(':').slice(0, 3).join(':') + '::/48';
    }
    const o = ip.split('.');
    if (o.length === 4) return o[0] + '.' + o[1] + '.' + o[2] + '.0/24';
    return '0';
  }
  coarsenUa(ua) {
    ua = (ua || '').toLowerCase();
    let b = 'other';
    if (ua.indexOf('firefox') >= 0) b = 'ff';
    else if (ua.indexOf('edg/') >= 0) b = 'edge';
    else if (ua.indexOf('chrome') >= 0) b = 'chrome';
    else if (ua.indexOf('safari') >= 0) b = 'safari';
    let os = 'other';
    if (ua.indexOf('windows') >= 0) os = 'win';
    else if (ua.indexOf('android') >= 0) os = 'android';
    else if (ua.indexOf('iphone') >= 0 || ua.indexOf('ipad') >= 0) os = 'ios';
    else if (ua.indexOf('mac os') >= 0) os = 'mac';
    else if (ua.indexOf('linux') >= 0) os = 'linux';
    return b + '/' + os;
  }

  // The daily, unlinkable visitor token.
  visitorToken(args) {
    this._ensureFresh();
    const material = [
      this.coarsenIp(args.ip),
      this.coarsenUa(args.ua),
      args.origin || '-',
    ].join('|');
    return crypto.createHmac('sha256', this._salt).update(material).digest('hex').slice(0, 16);
  }

  // Back-compat shim for old call sites that only had an IP.
  anonymizeIP(ip) {
    if (!ip) return 'unknown';
    this._ensureFresh();
    return crypto.createHmac('sha256', this._salt).update(this.coarsenIp(ip)).digest('hex').slice(0, 16);
  }
  anonymizeUA(ua) { return this.coarsenUa(ua); }

  scrubString(s) {
    if (typeof s !== 'string') return s;
    let out = s;
    for (const p of PII_PATTERNS) out = out.replace(p.re, p.tag);
    return out;
  }
  scrubUrl(raw) {
    if (!raw) return raw;
    const hadScheme = /^https?:\/\//i.test(raw);
    const base = 'http://wall.local';
    try {
      const u = new URL(raw, base); // resolves bare paths against a dummy base
      for (const k of Array.from(u.searchParams.keys())) {
        if (TRACKING_PARAMS.has(k.toLowerCase())) u.searchParams.delete(k);
      }
      u.username = ''; u.password = ''; u.hash = '';
      const full = this.scrubString(u.toString());
      // if caller gave a bare path, return a bare path
      return hadScheme ? full : full.replace(/^https?:\/\/[^/]+/, '');
    } catch (e) { return this.scrubString(raw); }
  }
  scrubPayload(obj, depth) {
    depth = depth || 0;
    if (depth > 6 || obj == null) return obj;
    if (typeof obj === 'string') return this.scrubString(obj);
    if (Array.isArray(obj)) return obj.map((v) => this.scrubPayload(v, depth + 1));
    if (typeof obj === 'object') {
      const out = {};
      for (const k of Object.keys(obj)) {
        if (/^(email|phone|name|user_id|userid|ssn|bsn|ip|address|fn|ln|em|ph)$/i.test(k)) {
          out[k] = '[redacted]';
        } else {
          out[k] = this.scrubPayload(obj[k], depth + 1);
        }
      }
      return out;
    }
    return obj;
  }

  state() {
    this._ensureFresh();
    return {
      saltEpoch: this._saltEpoch,
      saltFingerprint: crypto.createHash('sha256').update(this._salt).digest('hex').slice(0, 8),
      msUntilRotation: (this._saltEpoch + 1) * this.rotationMs - Date.now(),
    };
  }
}

module.exports = { Anonymizer, TRACKING_PARAMS };
