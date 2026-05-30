// Paramant Wall — Privacy Verifier — popup.js

const VERDICTS = {
  protected: {
    title: 'Protected', shield: '\u2713',
    sub: 'Tracking is routed through Paramant Wall',
  },
  partial: {
    title: 'Partly protected', shield: '!',
    sub: 'Enrolled, but some trackers bypass Wall',
  },
  unprotected: {
    title: 'Not protected', shield: '\u2715',
    sub: 'Trackers are reaching vendors directly',
  },
  clean: {
    title: 'No trackers seen', shield: '\u00b7',
    sub: 'No known tracking on this page yet',
  },
  unknown: {
    title: 'Unknown', shield: '\u00b7',
    sub: 'Not enough signal yet',
  },
};

function el(id) { return document.getElementById(id); }
function prettyTracker(t) {
  return t.replace('/tr', ' (Meta)').replace('/g/collect', '')
    .replace('sc.omtrdc.net', 'Adobe Analytics')
    .replace('piwik.pro', 'Piwik PRO')
    .replace('google-analytics.com', 'Google Analytics')
    .replace('googletagmanager.com', 'Google Tag Manager');
}

function render(state) {
  const v = state.verdict || 'unknown';
  const meta = VERDICTS[v] || VERDICTS.unknown;

  el('head').className = 'head ' + v;
  el('shield').textContent = meta.shield;
  el('vtitle').textContent = meta.title;
  el('vsub').textContent = meta.sub;
  el('host').innerHTML = '<span>site</span> ' + (state.host || '—');

  // attestation block
  const a = state.attest;
  const rows = [];
  if (!a) {
    rows.push(row('n', 'Contacting Wall…', ''));
  } else if (!a.enrolled) {
    rows.push(row('r', 'Enrolled with Wall', 'no'));
    rows.push(row('n', 'This domain is not a Wall customer', ''));
  } else {
    rows.push(row('g', 'Enrolled with Wall', 'yes'));
    if (a.valid === true) rows.push(row('g', 'Signature verified', 'Ed25519 \u2713'));
    else if (a.valid === null) rows.push(row('y', 'Signature present', 'unverified*'));
    else rows.push(row('r', 'Signature', 'INVALID'));
    if (a.keyMatchesPin === true) rows.push(row('g', 'Key matches pin', 'yes'));
    else if (a.keyMatchesPin === false) rows.push(row('r', 'Key matches pin', 'NO'));
    if (a.version) rows.push(row('n', 'Wall version', a.version));
    if (a.ts) rows.push(row('n', 'Attested', timeAgo(a.ts)));
  }
  let html = rows.join('');
  if (a && a.enrolled && a.features && a.features.length) {
    html += '<div class="feats">' +
      a.features.map((f) => '<span class="feat">' + f + '</span>').join('') + '</div>';
  }
  el('attest').innerHTML = html;

  // tracker evidence
  const direct = state.direct || [];
  const walled = state.walled || [];
  let list = '';
  direct.forEach((d) => {
    list += '<div class="li">' + prettyTracker(d) +
      '<span class="tag leak">DIRECT</span></div>';
  });
  if (walled.length) {
    list += '<div class="li">Paramant Wall relay' +
      '<span class="tag wall">ROUTED</span></div>';
  }
  if (!list) list = '<div class="empty">No tracking requests observed yet. Browse the page and reopen.</div>';
  el('trackers').innerHTML = list;

  // footnote for unverified Ed25519 (older Chromium)
  if (a && a.valid === null) {
    el('foot').innerHTML = '*Your browser build can\'t verify Ed25519 in-page yet, ' +
      'so the signature is shown as present but unverified. The enrollment check still holds. ' +
      'Update Chrome/Edge for full cryptographic verification.';
  }
}

function row(dot, lab, val) {
  return '<div class="arow"><span class="dot ' + dot + '"></span>' +
    '<span class="lab">' + lab + '</span>' +
    (val ? '<span class="val">' + val + '</span>' : '') + '</div>';
}
function timeAgo(ts) {
  const s = Math.round((Date.now() - ts) / 1000);
  if (s < 60) return s + 's ago';
  return Math.round(s / 60) + 'm ago';
}

function load() {
  chrome.tabs.query({ active: true, currentWindow: true }, (t) => {
    const tab = t && t[0];
    if (!tab) return;
    chrome.runtime.sendMessage({ type: 'getState', tabId: tab.id }, (state) => {
      if (chrome.runtime.lastError || !state) {
        render({ verdict: 'unknown', host: tab.url ? new URL(tab.url).hostname : '' });
        return;
      }
      render(state);
    });
  });
}

load();
setInterval(load, 1500); // live refresh while open
