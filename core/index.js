/**
 * PARAMANT CORE — entry point
 *
 * Wires the three pieces into one object the server can drop in:
 *   core.anon            -> Anonymizer (tokens, PII scrub, URL scrub)
 *   core.native          -> first-party RAM-only analytics
 *   core.ingest(event)   -> push through the k-anon gate to native
 *   core.state()         -> diagnostics for the dashboard / /health
 */
'use strict';
const { Anonymizer } = require('./anonymizer');
const { KAnonGate } = require('./kanon');
const { NativeAdapter } = require('./native');

function createCore(opts) {
  opts = opts || {};
  const anon = new Anonymizer();
  const native = new NativeAdapter({ retentionDays: opts.retentionDays || 30 });
  const gate = new KAnonGate({
    k: opts.k || parseInt(process.env.WALL_K, 10) || 5,
    ttlMs: (opts.bufferTtlMinutes || 30) * 60000,
    onFlush: function (events) { native.send(events); },
  });

  return {
    anon: anon,
    native: native,
    gate: gate,
    // Build + ingest an event from already-derived, anonymised fields.
    ingest: function (ev) {
      ev.ts = ev.ts || Date.now();
      return gate.ingest(ev);
    },
    state: function () {
      return {
        anonymizer: anon.state(),
        kanon: gate.state(),
        report: native.report(),
        range: native.reportRange(7),
      };
    },
  };
}

module.exports = { createCore };
