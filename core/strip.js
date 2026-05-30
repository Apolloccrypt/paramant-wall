/**
 * PARAMANT CORE — vendor strip engine
 *
 * Anonymises a tracker's collect URL/body before Wall forwards it to the real
 * vendor host (Piwik PRO, Adobe Analytics, Matomo, ...). Stable identifiers
 * become the daily-rotating visitor token; PII / IP / auth fields are dropped.
 */
'use strict';

// Fields we KEEP but pseudonymise (so per-vendor unique counts still work)
const PSEUDO_RE = /^(_id|uid|cid|vid|aid|mid|duid|_pk_id|visitor|distinct_id)/i;

function stripTrackerUrl(anon, rawUrl, stripFields, visitorToken) {
  let u;
  try { u = new URL(rawUrl); } catch (e) { return rawUrl; }
  const fields = (stripFields || []).map((f) => f.toLowerCase());

  for (const key of Array.from(u.searchParams.keys())) {
    const lk = key.toLowerCase();
    const hit = fields.some((f) => lk === f || lk.indexOf(f) === 0);
    if (hit) {
      if (PSEUDO_RE.test(lk)) u.searchParams.set(key, visitorToken);
      else u.searchParams.delete(key);
    }
  }
  return anon.scrubUrl(u.toString());
}

function stripTrackerBody(anon, body, stripFields, visitorToken) {
  if (!body) return body;
  try {
    const parsed = typeof body === 'object' ? body : JSON.parse(body);
    return JSON.stringify(anon.scrubPayload(parsed));
  } catch (e) {
    // Adobe AppMeasurement bodies are not JSON — scrub as text.
    return anon.scrubString(String(body));
  }
}

module.exports = { stripTrackerUrl, stripTrackerBody, PSEUDO_RE };
