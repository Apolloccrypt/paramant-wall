/**
 * PARAMANT CORE — k-anonymity gate
 *
 * Even without an identifier, a single rare event can re-identify someone
 * ("1 visitor from Reykjavik on /salaries at 03:14"). Stripping cookies does
 * not fix that; this does.
 *
 * Events are bucketed by quasi-identifiers (page + country + device + hour).
 * A bucket is only released to the analytics backend once it holds >= k
 * DISTINCT visitor tokens. Buckets that never reach k within the TTL are
 * DROPPED, never forwarded. Every released metric is therefore backed by at
 * least k real people, by construction.
 */
'use strict';

class KAnonGate {
  constructor(opts) {
    opts = opts || {};
    this.k = opts.k || 5;
    if (this.k < 2) throw new Error('k must be >= 2');
    this.ttlMs = opts.ttlMs || 30 * 60 * 1000;
    this.onFlush = opts.onFlush || function () {};
    this.buckets = new Map();
    const self = this;
    this._sweeper = setInterval(function () { self._sweep(); }, Math.min(this.ttlMs, 60000));
    if (this._sweeper.unref) this._sweeper.unref();
  }

  _bucketKey(ev) {
    const hour = new Date(ev.ts).toISOString().slice(0, 13);
    return [ev.event || 'pageview', ev.path || '/', ev.country || '??',
            ev.device || 'other', hour].join('|');
  }

  ingest(ev) {
    const key = this._bucketKey(ev);
    let b = this.buckets.get(key);
    if (!b) { b = { events: [], tokens: new Set(), firstSeen: Date.now() }; this.buckets.set(key, b); }
    b.events.push(ev);
    b.tokens.add(ev.visitor);
    if (b.tokens.size >= this.k) {
      this.buckets.delete(key);
      try { this.onFlush(b.events); } catch (e) { console.error('[kanon] flush error', e && e.message); }
      return { status: 'flushed', count: b.events.length };
    }
    return { status: 'buffered', have: b.tokens.size, need: this.k };
  }

  _sweep() {
    const now = Date.now();
    let dropped = 0;
    for (const [key, b] of this.buckets) {
      if (now - b.firstSeen > this.ttlMs) { this.buckets.delete(key); dropped += b.events.length; }
    }
    if (dropped) console.log('[kanon] dropped ' + dropped + ' sub-k events (privacy floor held)');
  }

  state() {
    let buffered = 0;
    for (const b of this.buckets.values()) buffered += b.events.length;
    return { k: this.k, openBuckets: this.buckets.size, bufferedEvents: buffered };
  }
  stop() { clearInterval(this._sweeper); }
}

module.exports = { KAnonGate };
