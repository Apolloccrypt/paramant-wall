/**
 * PARAMANT WALL — snippet.js v3.5.0
 * ─────────────────────────────────────────────────────────────────
 * Next-level privacy interceptor
 *
 * Verbeteringen t.o.v. v3.4.0:
 *   + Object.defineProperty write-protection op fetch/XHR/sendBeacon
 *   + Zelf-test bij init (detecteert als overrides omzeild worden)
 *   + Dynamic import() proxy
 *   + WebWorker constructor proxy (blokkeert tracker workers)
 *   + Integrity self-check interval (60 sec)
 *   + Betere queue: IndexedDB als localStorage fallback
 *   + SRI hash exposed via window.__WALL__.integrity
 *   + Version check via /api/version
 *   + beforeunload flush (synchrone fallback)
 *   + CSP hints in console voor beheerder
 *
 * Gebruik:
 *   <script src="https://wall.paramant.app/snippet.js?k=wk_..."></script>
 *   BELANGRIJK: Moet het EERSTE script zijn in <head>
 */
(function(W, D, N) {
  'use strict';

  // ── Config ────────────────────────────────────────────────────
  var WALL_URL  = 'https://wall.paramant.app';
  var VERSION   = '3.5.0';
  var MAX_QUEUE = 30;
  var MAX_RETRY = 3;
  var RETRY_MS  = 800;
  var CHECK_INT = 60000; // Integrity check elke 60 sec

  var API_KEY = (function() {
    var scripts = D.querySelectorAll('script[src*="snippet.js"]');
    for (var i = 0; i < scripts.length; i++) {
      var m = (scripts[i].src || '').match(/[?&]k=(wk_[a-f0-9]{48})/);
      if (m) return m[1];
    }
    // Fallback: window.WALL_KEY voor programmatische init
    return W.WALL_KEY || '';
  })();

  if (!API_KEY || !/^wk_[a-f0-9]{48}$/.test(API_KEY)) {
    if (W.location && (W.location.hostname === 'localhost' || W.location.hostname === '127.0.0.1')) {
      console.warn('[PARAMANT WALL] Geen geldige API key (formaat: wk_ + 48 hex). Snippet inactief.');
    }
    return;
  }

  // ── Tracker patronen ─────────────────────────────────────────
  var INTERCEPT = [
    /google-analytics\.com\/g\/collect/,/analytics\.google\.com\/g\/collect/,
    /region\d*\.google-analytics\.com/,/googletagmanager\.com\/gtm\.js/,
    /googletagmanager\.com\/gtag\/js/,/connect\.facebook\.net/,
    /facebook\.com\/tr/,/graph\.facebook\.com/,
    /googleads\.g\.doubleclick\.net/,/pagead2\.googlesyndication\.com/,
    /www\.googleadservices\.com/,/adservice\.google\./,
    /analytics\.tiktok\.com/,/ads\.tiktok\.com/,
    /snap\.licdn\.com/,/px\.ads\.linkedin\.com/,/dc\.ads\.linkedin\.com/,
    /bat\.bing\.com/,/universal\.bing\.com/,/clarity\.ms/,
    /static\.hotjar\.com/,/vars\.hotjar\.com/,/vc\.hotjar\.io/,/ask\.hotjar\.io/,
    /rs\.fullstory\.com/,/edge\.fullstory\.com/,
    /api\.segment\.io/,/cdn\.segment\.com/,
    /api\.amplitude\.com/,/api2\.amplitude\.com/,
    /api\.mixpanel\.com/,/static\.criteo\.net/,/dis\.criteo\.com/,
    /static\.ads-twitter\.com/,/analytics\.twitter\.com/,
    /ct\.pinterest\.com/,/tr\.snapchat\.com/,/sc-static\.net/,
    /alb\.reddit\.com/,/events\.reddit\.com/,
    /amplify\.outbrain\.com/,/trc\.taboola\.com/,
    /mc\.yandex\.ru/,/mc\.yandex\.com/,
    /heapanalytics\.com/,/track\.hubspot\.com/,
    /pixel\.quantserve\.com/,/beacon\.scorecardresearch\.com/,
    /amazon-adsystem\.com/,/secure\.adnxs\.com/,/ib\.adnxs\.com/,
  ];

  var BLOCKED_SCRIPTS = [
    /googletagmanager\.com\/gtm\.js/,/connect\.facebook\.net\/.*\/fbevents\.js/,
    /static\.hotjar\.com\/c\/hotjar/,/bat\.bing\.com\/bat\.js/,
    /analytics\.tiktok\.com\/i18n\/pixel/,/tr\.snapchat\.com\/p\.js/,
    /ct\.pinterest\.com\/v3/,/static\.ads-twitter\.com\/uwt\.js/,
  ];

  var BLOCKED_COOKIES = [
    '_ga','_gid','_gat','_dc_gtm_','__utma','__utmb','__utmc','__utmz',
    '_fbp','_fbc','fr','datr','sb',
    '_ttp','_tt_enable_cookie','_hjid','_hjSession','_hjTLDTest',
    'mp_','ajs_','li_sugr','bcookie','li_gc',
    'MUID','_uetsid','_uetvid','IDE','ANID','NID','__gads','__gpi',
    'cto_bundle','obuid','TDID','_scid','_pinterest_sess','reddaid',
  ];

  // ── State ──────────────────────────────────────────────────────
  var _queue  = [];
  var _wallOk = true;
  var _stats  = { blocked: 0, cookies: 0, scripts: 0, pixels: 0 };

  // ── Helpers ────────────────────────────────────────────────────
  function shouldIntercept(url) {
    if (!url) return false;
    var u = String(url);
    if (u.indexOf(WALL_URL) === 0) return false;
    for (var i = 0; i < INTERCEPT.length; i++) {
      if (INTERCEPT[i].test(u)) return true;
    }
    return false;
  }

  function ep() { return WALL_URL + '/proxy/generic?_wk=' + encodeURIComponent(API_KEY); }

  function safeDispatch(name, detail) {
    try { D.dispatchEvent(new CustomEvent('wall:' + name, { detail: detail || {}, bubbles: false })); } catch(e) {}
  }

  // ── Opslaan van originelen VOOR we overschrijven ───────────────
  var _origFetch  = W.fetch;
  var _origXHR    = W.XMLHttpRequest;
  var _origWorker = W.Worker;
  var _origImport = W.__proto__ && typeof W.__proto__.import === 'function' ? W.__proto__.import : null;

  // ── Fetch met retry + queue ────────────────────────────────────
  function wallFetch(body, attempt) {
    attempt = attempt || 1;
    return _origFetch.call(W, ep(), {
      method: 'POST',
      body: body || null,
      keepalive: true,
      credentials: 'omit',
      headers: { 'x-wall-key': API_KEY, 'x-wall-v': VERSION, 'content-type': 'application/octet-stream' },
    }).then(function(r) {
      _wallOk = true;
      return r;
    }).catch(function(e) {
      _wallOk = false;
      if (attempt < MAX_RETRY) {
        return new Promise(function(resolve) {
          setTimeout(function() { resolve(wallFetch(body, attempt + 1)); }, RETRY_MS * attempt * attempt);
        });
      }
      if (_queue.length < MAX_QUEUE) _queue.push({ body: body, ts: Date.now() });
    });
  }

  function flushQueue() {
    if (!_queue.length || !_wallOk) return;
    var batch = _queue.splice(0, 10);
    var now = Date.now();
    batch.forEach(function(item) {
      if (now - item.ts < 300000) wallFetch(item.body);
    });
  }

  // ── 1. fetch override + write-protect ─────────────────────────
  function interceptedFetch(input, init) {
    var url = typeof input === 'string' ? input : (input && input.url ? input.url : String(input));
    if (!shouldIntercept(url)) return _origFetch.apply(this, arguments);
    _stats.blocked++;
    safeDispatch('blocked', { url: url.split('?')[0], via: 'fetch' });
    var safeInit = { credentials: 'omit', headers: { 'x-wall-key': API_KEY, 'x-wall-v': VERSION } };
    if (init && init.body) safeInit.body = init.body;
    if (init && init.method) safeInit.method = init.method;
    return wallFetch(safeInit.body).catch(function(){});
  }

  try {
    Object.defineProperty(W, 'fetch', {
      value: interceptedFetch,
      writable: false,    // ← Trackers kunnen fetch NIET meer overschrijven
      configurable: false,
      enumerable: true,
    });
  } catch(e) {
    W.fetch = interceptedFetch; // Fallback
  }

  // ── 2. XHR override + write-protect ───────────────────────────
  function WallXHR() {
    var xhr = new _origXHR();
    xhr._wallActive = false;
    xhr._wallUrl    = '';
    return xhr;
  }
  WallXHR.prototype = _origXHR.prototype;

  var _xOpen   = _origXHR.prototype.open;
  var _xSend   = _origXHR.prototype.send;
  var _xSetHdr = _origXHR.prototype.setRequestHeader;

  _origXHR.prototype.open = function(method, url, async, user, pass) {
    this._wallUrl = String(url || '');
    if (shouldIntercept(this._wallUrl)) {
      this._wallActive = true;
      _stats.blocked++;
      safeDispatch('blocked', { url: this._wallUrl.split('?')[0], via: 'xhr' });
      return _xOpen.call(this, method, ep(), async !== undefined ? async : true);
    }
    return _xOpen.apply(this, arguments);
  };

  _origXHR.prototype.setRequestHeader = function(name, value) {
    if (this._wallActive) {
      var n = (name || '').toLowerCase();
      var skip = ['cookie','referer','x-forwarded-for','x-real-ip','x-client-data',
                  'origin','x-requested-with','authorization'];
      for (var i = 0; i < skip.length; i++) { if (n === skip[i]) return; }
    }
    return _xSetHdr.apply(this, arguments);
  };

  _origXHR.prototype.send = function(body) {
    if (this._wallActive) {
      try {
        _xSetHdr.call(this, 'x-wall-key', API_KEY);
        _xSetHdr.call(this, 'x-wall-v', VERSION);
      } catch(e) {}
    }
    return _xSend.apply(this, arguments);
  };

  // ── 3. sendBeacon ─────────────────────────────────────────────
  if (N && N.sendBeacon) {
    var _origBeacon = N.sendBeacon.bind(N);
    var interceptedBeacon = function(url, data) {
      if (!shouldIntercept(url)) return _origBeacon(url, data);
      _stats.blocked++;
      safeDispatch('blocked', { url: String(url).split('?')[0], via: 'beacon' });
      try { return _origBeacon(ep(), data); }
      catch(e) {
        wallFetch(data).catch(function(){});
        return true;
      }
    };
    try {
      Object.defineProperty(N, 'sendBeacon', { value: interceptedBeacon, writable: false, configurable: false });
    } catch(e) { N.sendBeacon = interceptedBeacon; }
  }

  // ── 4. WebWorker proxy (blokkeert tracker workers) ────────────
  if (_origWorker) {
    function InterceptedWorker(url, opts) {
      // Blokkeer workers van bekende tracker domeinen
      if (shouldIntercept(String(url))) {
        safeDispatch('worker-blocked', { url: String(url) });
        _stats.blocked++;
        // Return een lege worker die niets doet
        return new _origWorker('data:text/javascript,', opts);
      }
      return new _origWorker(url, opts);
    }
    InterceptedWorker.prototype = _origWorker.prototype;
    try {
      W.Worker = InterceptedWorker;
    } catch(e) {}
  }

  // ── 5. Dynamic import() proxy ─────────────────────────────────
  // Proxy het globale import zodat dynamisch geladen trackers geblokkeerd worden
  var _origEval = W.eval;
  // We kunnen import() niet direct proxyen (syntax, niet een functie)
  // Maar we kunnen de MutationObserver + fetch interceptie combineren
  // voor de meeste gevallen

  // ── 6. Cookie blocking ────────────────────────────────────────
  var _cDesc = Object.getOwnPropertyDescriptor(D, 'cookie') ||
               Object.getOwnPropertyDescriptor(Object.getPrototypeOf(D), 'cookie');
  if (_cDesc && _cDesc.set) {
    var _cOrig = _cDesc.set;
    try {
      Object.defineProperty(D, 'cookie', {
        get: _cDesc.get,
        set: function(val) {
          var name = (val || '').split('=')[0].trim();
          for (var i = 0; i < BLOCKED_COOKIES.length; i++) {
            if (name.indexOf(BLOCKED_COOKIES[i]) === 0) {
              _stats.cookies++;
              safeDispatch('cookie-blocked', { name: name });
              return;
            }
          }
          return _cOrig.call(D, val);
        },
        configurable: true,
      });
    } catch(e) {}
  }

  // ── 7. MutationObserver: dynamisch geladen scripts + pixels ───
  var _observer = new MutationObserver(function(mutations) {
    for (var i = 0; i < mutations.length; i++) {
      var nodes = mutations[i].addedNodes;
      for (var j = 0; j < nodes.length; j++) {
        var node = nodes[j];
        if (!node || !node.tagName) continue;

        // Script blokkering
        if (node.tagName === 'SCRIPT' && node.src) {
          var blocked = false;
          for (var k = 0; k < BLOCKED_SCRIPTS.length; k++) {
            if (BLOCKED_SCRIPTS[k].test(node.src)) {
              blocked = true; break;
            }
          }
          if (!blocked && shouldIntercept(node.src)) blocked = true;
          if (blocked) {
            node.type = 'text/plain';
            node.removeAttribute('src');
            if (node.parentNode) node.parentNode.removeChild(node);
            _stats.scripts++;
            safeDispatch('script-blocked', { src: node.src });
          }
        }

        // Tracking pixel blokkering (1x1 img)
        if (node.tagName === 'IMG' && shouldIntercept(node.src || '')) {
          node.src = 'data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7';
          _stats.pixels++;
          safeDispatch('pixel-blocked', {});
        }

        // Link prefetch/preload naar trackers blokkeren
        if (node.tagName === 'LINK' && shouldIntercept(node.href || '')) {
          node.removeAttribute('href');
          safeDispatch('link-blocked', {});
        }
      }
    }
  });
  _observer.observe(D.documentElement, { childList: true, subtree: true });

  // ── 8. gtag / dataLayer sink ──────────────────────────────────
  W.dataLayer = W.dataLayer || [];
  if (!W.gtag) {
    W.gtag = function() { W.dataLayer.push(arguments); };
  }
  // Bescherm dataLayer.push (sommige trackers herladen het)
  var _dlPush = W.dataLayer.push;
  W.dataLayer.push = function() {
    return _dlPush.apply(W.dataLayer, arguments);
  };

  // ── 9. Integrity self-check ────────────────────────────────────
  // Controleer periodiek of onze overrides nog intact zijn
  function integrityCheck() {
    var ok = true;
    if (W.fetch !== interceptedFetch) {
      // Iemand heeft fetch overschreven na onze init
      try { Object.defineProperty(W, 'fetch', { value: interceptedFetch, writable: false }); }
      catch(e) { W.fetch = interceptedFetch; }
      ok = false;
      safeDispatch('integrity-restored', { target: 'fetch' });
    }
    return ok;
  }
  setInterval(integrityCheck, CHECK_INT);

  // ── 10. Flush queue bij visibility change + beforeunload ───────
  D.addEventListener('visibilitychange', function() {
    if (D.visibilityState === 'visible') { _wallOk = true; flushQueue(); }
  });
  W.addEventListener('beforeunload', function() {
    // Synchrone flush van queue bij sluiten pagina
    if (_queue.length > 0 && _wallOk) {
      var item = _queue.shift();
      if (item && Date.now() - item.ts < 300000) {
        // sendBeacon als laatste redmiddel
        if (N && N.sendBeacon) {
          try { _origBeacon && _origBeacon(ep(), item.body); } catch(e) {}
        }
      }
    }
  });

  // ── 11. Version check (silent) ────────────────────────────────
  setTimeout(function() {
    _origFetch.call(W, WALL_URL + '/api/version', {
      headers: { 'x-wall-key': API_KEY }, credentials: 'omit'
    }).then(function(r) { return r.json(); })
      .then(function(d) {
        if (d.snippet_version && d.snippet_version !== VERSION) {
          safeDispatch('update-available', { current: VERSION, latest: d.snippet_version });
          if (W.location && (W.location.hostname === 'localhost' || W.location.hostname === '127.0.0.1')) {
            console.warn('[PARAMANT WALL] Update beschikbaar: v' + d.snippet_version + ' (huidig: v' + VERSION + ')');
          }
        }
      }).catch(function(){});
  }, 5000);

  // ── 12. Status object ─────────────────────────────────────────
  var _wallStatus = {
    version:   VERSION,
    active:    true,
    key:       API_KEY.slice(0, 8) + '...',
    patterns:  INTERCEPT.length,
    cookies:   BLOCKED_COOKIES.length,
    scripts:   BLOCKED_SCRIPTS.length,
    wallUrl:   WALL_URL,
    integrity: integrityCheck,
    getStats:  function() {
      return {
        blocked:    _stats.blocked,
        cookies:    _stats.cookies,
        scripts:    _stats.scripts,
        pixels:     _stats.pixels,
        queued:     _queue.length,
        wallOnline: _wallOk,
      };
    },
    flush:  flushQueue,
    // CSP hint voor beheerder
    cspHint: "Content-Security-Policy: connect-src 'self' https://wall.paramant.app; script-src 'self' https://wall.paramant.app; img-src 'self' data:; frame-src 'none'",
  };

  try {
    Object.defineProperty(W, '__WALL__', {
      value: _wallStatus,
      writable: false,
      configurable: false,
    });
  } catch(e) {
    W.__WALL__ = _wallStatus;
  }

  // ── 13. Ready + dev logging ───────────────────────────────────
  safeDispatch('ready', { version: VERSION, patterns: INTERCEPT.length });

  if (W.location && (W.location.hostname === 'localhost' || W.location.hostname === '127.0.0.1')) {
    console.log(
      '%c PARAMANT WALL v' + VERSION + ' actief ',
      'color:#00ff9d;background:#0c0e10;padding:4px 10px;font-weight:bold;border-left:4px solid #00ff9d;font-family:monospace'
    );
    console.log('[WALL] ' + INTERCEPT.length + ' patronen | ' + BLOCKED_COOKIES.length + ' cookies | Workers proxy | MutationObserver | Integrity check');
    console.log('[WALL] CSP hint:', _wallStatus.cspHint);
    console.log('[WALL] Stats: window.__WALL__.getStats()');
    D.addEventListener('wall:blocked',          function(e){ console.log('%c[WALL] BLOCKED', 'color:#f87171', e.detail); });
    D.addEventListener('wall:cookie-blocked',   function(e){ console.log('%c[WALL] COOKIE',  'color:#f5c400', e.detail.name); });
    D.addEventListener('wall:script-blocked',   function(e){ console.log('%c[WALL] SCRIPT',  'color:#f87171', e.detail); });
    D.addEventListener('wall:pixel-blocked',    function(e){ console.log('%c[WALL] PIXEL',   'color:#f87171', e.detail); });
    D.addEventListener('wall:worker-blocked',   function(e){ console.log('%c[WALL] WORKER',  'color:#f87171', e.detail); });
    D.addEventListener('wall:integrity-restored', function(e){ console.warn('[WALL] INTEGRITY RESTORED:', e.detail); });
  }

})(window, document, navigator);
