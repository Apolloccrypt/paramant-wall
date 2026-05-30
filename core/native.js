/**
 * PARAMANT CORE — native analytics adapter
 *
 * A first-party, RAM-only analytics backend. Events fold immediately into
 * rolling aggregate counters and the individual events are discarded. Even
 * Wall itself only ever knows COUNTS — there is no event log to leak.
 *
 * This is the "data that doesn't exist can't leak" option, and the piece the
 * original proxy-only Wall never had: customers who don't want GA4/Meta at all
 * can run pure first-party analytics through the same k-anon gate.
 */
'use strict';

function safeHost(url) { try { return new URL(url).host; } catch (e) { return '(other)'; } }

class NativeAdapter {
  constructor(opts) {
    opts = opts || {};
    this.name = 'native';
    this.retentionDays = opts.retentionDays || 30;
    this.days = new Map(); // 'YYYY-MM-DD' -> aggregates
  }
  _day(ts) { return new Date(ts).toISOString().slice(0, 10); }
  _bucket(day) {
    let d = this.days.get(day);
    if (!d) {
      d = { pageviews: 0, visitors: new Set(), events: new Map(), pages: new Map(),
            referrers: new Map(), countries: new Map(), devices: new Map() };
      this.days.set(day, d);
      this._prune();
    }
    return d;
  }
  _inc(m, k) { if (k) m.set(k, (m.get(k) || 0) + 1); }
  _prune() {
    const keep = this.retentionDays;
    const sorted = Array.from(this.days.keys()).sort();
    while (sorted.length > keep) this.days.delete(sorted.shift());
  }

  send(events) {
    for (const ev of events) {
      const d = this._bucket(this._day(ev.ts));
      if ((ev.event || 'pageview') === 'pageview') d.pageviews++;
      d.visitors.add(ev.visitor);
      this._inc(d.events, ev.event || 'pageview');
      this._inc(d.pages, ev.path);
      this._inc(d.referrers, ev.referrer ? safeHost(ev.referrer) : '(direct)');
      this._inc(d.countries, ev.country);
      this._inc(d.devices, ev.device);
    }
    return { ok: true, sent: events.length };
  }

  report(day) {
    day = day || this._day(Date.now());
    const d = this.days.get(day);
    if (!d) return null;
    const top = function (m, n) {
      n = n || 10;
      return Array.from(m.entries()).sort((a, b) => b[1] - a[1]).slice(0, n)
        .map((e) => ({ key: e[0], count: e[1] }));
    };
    return {
      day,
      pageviews: d.pageviews,
      uniqueVisitors: d.visitors.size,
      events: top(d.events),
      topPages: top(d.pages),
      topReferrers: top(d.referrers),
      countries: top(d.countries),
      devices: top(d.devices),
    };
  }
  reportRange(days) {
    days = days || 7;
    const out = [];
    const now = Date.now();
    for (let i = days - 1; i >= 0; i--) {
      const day = new Date(now - i * 86400000).toISOString().slice(0, 10);
      out.push(this.report(day) || { day, pageviews: 0, uniqueVisitors: 0 });
    }
    return out;
  }
}

module.exports = { NativeAdapter };
