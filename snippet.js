/**
 * PARAMANT WALL — snippet.js v3.4.0
 * ─────────────────────────────────────────────────────────────────
 * Productie-klare drop-in privacy interceptor
 *
 * Onderschept:
 *   • fetch (alle methodes)
 *   • XMLHttpRequest (open/send/setRequestHeader)
 *   • navigator.sendBeacon
 *   • document.cookie (tracking prefixes geblokkeerd)
 *   • Dynamisch geladen scripts via MutationObserver
 *   • window.gtag / dataLayer.push (GTM sink)
 *
 * Features:
 *   • Offline queue — requests gebufferd als Wall tijdelijk down is
 *   • Retry met exponential backoff (max 2 pogingen)
 *   • Geen URL lekkage naar Wall server
 *   • Geen logs in productie
 *   • window.__WALL__ status object voor debugging
 *   • wall:ready + wall:blocked events voor integraties
 *
 * Gebruik:
 *   <script src="https://wall.paramant.app/snippet.js?k=wk_..."></script>
 *
 * Licentie: MIT — PARAMANT 2026
 */
(function(W, D, N) {
  'use strict';

  // ── Config ────────────────────────────────────────────────────
  var WALL_URL = 'https://wall.paramant.app';
  var VERSION  = '3.4.0';
  var MAX_QUEUE = 20;      // Max gebufferde requests bij Wall down
  var MAX_RETRY = 2;       // Max herhaalpogingen
  var RETRY_MS  = 1000;    // Basis retry delay (exponential backoff)

  var API_KEY = (function() {
    var scripts = D.querySelectorAll('script[src*="snippet.js"]');
    for (var i = 0; i < scripts.length; i++) {
      var m = (scripts[i].src || '').match(/[?&]k=(wk_[a-f0-9]{48})/);
      if (m) return m[1];
    }
    return '';
  })();

  // Valideer key formaat
  if (!API_KEY || !/^wk_[a-f0-9]{48}$/.test(API_KEY)) {
    if (W.location && (W.location.hostname === 'localhost' || W.location.hostname === '127.0.0.1')) {
      console.warn('[PARAMANT WALL] Geen geldige API key. Gebruik: ?k=wk_...');
    }
    return;
  }

  // ── Tracker patronen (45 stuks) ───────────────────────────────
  var INTERCEPT = [
    // Google Analytics 4 + GTM
    /google-analytics\.com\/g\/collect/,
    /analytics\.google\.com\/g\/collect/,
    /region\d*\.google-analytics\.com/,
    /googletagmanager\.com\/gtm\.js/,
    /googletagmanager\.com\/gtag\/js/,
    // Meta / Facebook
    /connect\.facebook\.net/,
    /facebook\.com\/tr/,
    /graph\.facebook\.com/,
    // Google Ads / DoubleClick
    /googleads\.g\.doubleclick\.net/,
    /pagead2\.googlesyndication\.com/,
    /www\.googleadservices\.com/,
    /adservice\.google\./,
    // TikTok
    /analytics\.tiktok\.com/,
    /ads\.tiktok\.com/,
    /business\.tiktok\.com/,
    // LinkedIn
    /snap\.licdn\.com/,
    /px\.ads\.linkedin\.com/,
    /dc\.ads\.linkedin\.com/,
    // Microsoft Ads + Clarity
    /bat\.bing\.com/,
    /universal\.bing\.com/,
    /clarity\.ms/,
    // Hotjar
    /static\.hotjar\.com/,
    /vars\.hotjar\.com/,
    /vc\.hotjar\.io/,
    /ask\.hotjar\.io/,
    // FullStory
    /rs\.fullstory\.com/,
    /edge\.fullstory\.com/,
    // Segment
    /api\.segment\.io/,
    /cdn\.segment\.com/,
    // Amplitude
    /api\.amplitude\.com/,
    /api2\.amplitude\.com/,
    // Mixpanel
    /api\.mixpanel\.com/,
    // Criteo
    /static\.criteo\.net/,
    /dis\.criteo\.com/,
    // Twitter / X
    /static\.ads-twitter\.com/,
    /analytics\.twitter\.com/,
    // Pinterest
    /ct\.pinterest\.com/,
    // Snapchat
    /tr\.snapchat\.com/,
    /sc-static\.net/,
    // Reddit
    /alb\.reddit\.com/,
    /events\.reddit\.com/,
    // Outbrain / Taboola
    /amplify\.outbrain\.com/,
    /trc\.taboola\.com/,
    // Yandex Metrika
    /mc\.yandex\.ru/,
    /mc\.yandex\.com/,
    // Heap / HubSpot / Quantcast / Comscore
    /heapanalytics\.com/,
    /track\.hubspot\.com/,
    /pixel\.quantserve\.com/,
    /beacon\.scorecardresearch\.com/,
    // New Relic / Datadog (optioneel — uitcommentariëren indien gewenst)
    // /bam\.nr-data\.net/,
    // /browser-intake-datadoghq\.com/,
    // Amazon Ads / AppNexus
    /amazon-adsystem\.com/,
    /secure\.adnxs\.com/,
    /ib\.adnxs\.com/,
  ];

  // ── Geblokkeerde script src patronen (dynamisch geladen) ──────
  var BLOCKED_SCRIPTS = [
    /googletagmanager\.com\/gtm\.js/,
    /connect\.facebook\.net\/.*\/fbevents\.js/,
    /static\.hotjar\.com\/c\/hotjar/,
    /static\.ads-twitter\.com\/uwt\.js/,
    /snap\.licdn\.com\/li\.lms-analytics/,
    /bat\.bing\.com\/bat\.js/,
    /analytics\.tiktok\.com\/i18n\/pixel/,
    /tr\.snapchat\.com\/p\.js/,
    /ct\.pinterest\.com\/v3/,
  ];

  // ── Geblokkeerde cookie prefixes ──────────────────────────────
  var BLOCKED_COOKIES = [
    '_ga','_gid','_gat','_dc_gtm_','__utma','__utmb','__utmc','__utmz',
    '_fbp','_fbc','fr','datr','sb',
    '_ttp','_tt_enable_cookie','_tt_uid',
    '_hjid','_hjSession','_hjTLDTest','_hjAbsoluteSessionInProgress',
    'mp_','ajs_user_id','ajs_anonymous_id','ajs_group_id',
    'li_sugr','bcookie','li_gc','UserMatchHistory',
    'MUID','_uetsid','_uetvid','MSPTC',
    'IDE','ANID','NID','__gads','__gpi',
    'cto_bundle','obuid','TDID','TTDOptOut',
    '_scid','_scid_r','_sctr',
    '_pinterest_sess','_pinterest_ct_ua',
    'reddaid','_reddit',
  ];

  // ── State ──────────────────────────────────────────────────────
  var _queue   = [];     // Offline queue
  var _wallOk  = true;   // Wall beschikbaar?
  var _blocked = 0;      // Teller voor stats

  // ── Helpers ────────────────────────────────────────────────────
  function shouldIntercept(url) {
    if (!url) return false;
    var u = String(url);
    if (u.indexOf(WALL_URL) === 0) return false; // nooit onszelf
    for (var i = 0; i < INTERCEPT.length; i++) {
      if (INTERCEPT[i].test(u)) return true;
    }
    return false;
  }

  function wallEndpoint() {
    return WALL_URL + '/proxy/generic?_wk=' + encodeURIComponent(API_KEY);
  }

  function wallHeaders(extra) {
    var h = { 'x-wall-key': API_KEY };
    if (extra) { for (var k in extra) { if (Object.prototype.hasOwnProperty.call(extra, k)) h[k] = extra[k]; } }
    return h;
  }

  function dispatch(name, detail) {
    try { D.dispatchEvent(new CustomEvent('wall:' + name, { detail: detail, bubbles: false })); } catch(e) {}
  }

  // ── Retry fetch met exponential backoff ───────────────────────
  var _origFetch = W.fetch;
  function wallFetch(body, attempt) {
    attempt = attempt || 1;
    return _origFetch.call(W, wallEndpoint(), {
      method: 'POST',
      body: body || null,
      keepalive: true,
      headers: wallHeaders({ 'content-type': 'application/json' }),
    }).then(function(r) {
      _wallOk = true;
      return r;
    }).catch(function(e) {
      if (attempt < MAX_RETRY) {
        return new Promise(function(resolve) {
          setTimeout(function() { resolve(wallFetch(body, attempt + 1)); }, RETRY_MS * attempt);
        });
      }
      // Wall down: queue voor later
      _wallOk = false;
      if (_queue.length < MAX_QUEUE) _queue.push({ body: body, ts: Date.now() });
      throw e;
    });
  }

  // Verwerk queue wanneer Wall weer bereikbaar is
  function flushQueue() {
    if (!_queue.length) return;
    var toSend = _queue.splice(0, 5); // Max 5 per flush
    toSend.forEach(function(item) {
      // Verwijder requests ouder dan 5 minuten
      if (Date.now() - item.ts > 300000) return;
      wallFetch(item.body).catch(function(){});
    });
  }
  // Probeer queue te flushen als page focus terugkeert
  D.addEventListener('visibilitychange', function() {
    if (D.visibilityState === 'visible') flushQueue();
  });

  // ── 1. Intercept fetch ─────────────────────────────────────────
  W.fetch = function(input, init) {
    var url = typeof input === 'string' ? input
            : (input && input.url) ? input.url
            : String(input);

    if (!shouldIntercept(url)) return _origFetch.apply(this, arguments);

    _blocked++;
    dispatch('blocked', { url: url.split('?')[0] });

    // Sanitize init: verwijder cookie + tracking headers
    var safeInit = {};
    if (init) {
      for (var k in init) {
        if (Object.prototype.hasOwnProperty.call(init, k) && k !== 'credentials') {
          safeInit[k] = init[k];
        }
      }
    }
    safeInit.headers = wallHeaders();
    safeInit.credentials = 'omit'; // Nooit cookies meesturen

    return _origFetch.call(W, wallEndpoint(), safeInit).catch(function(e) {
      if (_queue.length < MAX_QUEUE) _queue.push({ body: safeInit.body || null, ts: Date.now() });
    });
  };

  // ── 2. Intercept XMLHttpRequest ────────────────────────────────
  var XHR      = W.XMLHttpRequest;
  var _xOpen   = XHR.prototype.open;
  var _xSend   = XHR.prototype.send;
  var _xSetHdr = XHR.prototype.setRequestHeader;

  XHR.prototype.open = function(method, url, async, user, pass) {
    this._wallUrl = String(url);
    if (shouldIntercept(this._wallUrl)) {
      this._wallActive = true;
      _blocked++;
      dispatch('blocked', { url: this._wallUrl.split('?')[0] });
      return _xOpen.call(this, method, wallEndpoint(), async !== undefined ? async : true);
    }
    return _xOpen.apply(this, arguments);
  };

  XHR.prototype.setRequestHeader = function(name, value) {
    if (this._wallActive) {
      var n = (name || '').toLowerCase();
      // Blokkeer tracking + privacy-gevoelige headers
      var blocked = ['cookie','referer','x-forwarded-for','x-real-ip',
                     'x-client-data','via','true-client-ip'];
      for (var i = 0; i < blocked.length; i++) {
        if (n === blocked[i]) return;
      }
    }
    return _xSetHdr.apply(this, arguments);
  };

  XHR.prototype.send = function(body) {
    if (this._wallActive) {
      try {
        _xSetHdr.call(this, 'x-wall-key', API_KEY);
        _xSetHdr.call(this, 'x-wall-v', VERSION);
      } catch(e) {}
    }
    return _xSend.apply(this, arguments);
  };

  // ── 3. Intercept sendBeacon ────────────────────────────────────
  if (N && N.sendBeacon) {
    var _origBeacon = N.sendBeacon.bind(N);
    N.sendBeacon = function(url, data) {
      if (!shouldIntercept(url)) return _origBeacon(url, data);
      _blocked++;
      dispatch('blocked', { url: String(url).split('?')[0], via: 'beacon' });
      try {
        return _origBeacon(wallEndpoint(), data);
      } catch(e) {
        // Fallback: fetch keepalive
        _origFetch.call(W, wallEndpoint(), {
          method: 'POST', body: data, keepalive: true,
          headers: wallHeaders(), credentials: 'omit',
        }).catch(function(){});
        return true;
      }
    };
  }

  // ── 4. Blokkeer tracking cookies ──────────────────────────────
  var _cDesc = Object.getOwnPropertyDescriptor(D, 'cookie') ||
               Object.getOwnPropertyDescriptor(Object.getPrototypeOf(D), 'cookie');
  if (_cDesc && _cDesc.set) {
    var _cOrigSet = _cDesc.set;
    Object.defineProperty(D, 'cookie', {
      get: _cDesc.get,
      set: function(val) {
        var name = (val || '').split('=')[0].trim();
        for (var i = 0; i < BLOCKED_COOKIES.length; i++) {
          if (name.indexOf(BLOCKED_COOKIES[i]) === 0) {
            dispatch('cookie-blocked', { name: name });
            return;
          }
        }
        return _cOrigSet.call(D, val);
      },
      configurable: true,
    });
  }

  // ── 5. Sink window.gtag / dataLayer ───────────────────────────
  // Onderschept GTM/gtag VOOR het data naar Google stuurt
  W.dataLayer = W.dataLayer || [];
  var _dlPush = Array.prototype.push;
  W.dataLayer.push = function() {
    // Laat door — events worden toch onderschept via fetch/XHR
    return _dlPush.apply(W.dataLayer, arguments);
  };
  // gtag sink: accepteert calls maar blokkeert de uitstroom via fetch
  if (!W.gtag) {
    W.gtag = function() {
      W.dataLayer.push(arguments);
    };
  }

  // ── 6. MutationObserver: blokkeer dynamisch geladen trackers ──
  var _observer = new MutationObserver(function(mutations) {
    for (var i = 0; i < mutations.length; i++) {
      var nodes = mutations[i].addedNodes;
      for (var j = 0; j < nodes.length; j++) {
        var node = nodes[j];
        if (node.tagName === 'SCRIPT' && node.src) {
          for (var k = 0; k < BLOCKED_SCRIPTS.length; k++) {
            if (BLOCKED_SCRIPTS[k].test(node.src)) {
              node.src = ''; // Leeghalen voor het geladen wordt
              node.type = 'text/plain'; // Prevent execution
              if (node.parentNode) node.parentNode.removeChild(node);
              dispatch('script-blocked', { src: node.src });
              _blocked++;
              break;
            }
          }
        }
        // Blokkeer tracking pixels (img met src naar trackers)
        if (node.tagName === 'IMG' && node.src) {
          if (shouldIntercept(node.src)) {
            node.src = 'data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7';
            dispatch('pixel-blocked', {});
            _blocked++;
          }
        }
      }
    }
  });
  _observer.observe(D.documentElement, { childList: true, subtree: true });

  // ── 7. Status object ──────────────────────────────────────────
  W.__WALL__ = {
    version:   VERSION,
    active:    true,
    key:       API_KEY.slice(0, 8) + '...',
    patterns:  INTERCEPT.length,
    cookies:   BLOCKED_COOKIES.length,
    scripts:   BLOCKED_SCRIPTS.length,
    wallUrl:   WALL_URL,
    getStats:  function() {
      return {
        blocked:   _blocked,
        queued:    _queue.length,
        wallOnline: _wallOk,
      };
    },
    flush: flushQueue,
  };

  // ── 8. Ready event ────────────────────────────────────────────
  dispatch('ready', {
    version:  VERSION,
    patterns: INTERCEPT.length,
    key:      API_KEY.slice(0, 8) + '...',
  });

  // Dev logging
  if (W.location && (W.location.hostname === 'localhost' || W.location.hostname === '127.0.0.1')) {
    console.log(
      '%c[PARAMANT WALL] v' + VERSION + ' actief — ' + INTERCEPT.length + ' patronen | ' +
      BLOCKED_COOKIES.length + ' cookies | MutationObserver aan',
      'color:#00ff9d;background:#0c0e10;padding:3px 8px;font-weight:bold;border-left:3px solid #00ff9d'
    );
    D.addEventListener('wall:blocked',        function(e){ console.log('[WALL] BLOCKED:', e.detail); });
    D.addEventListener('wall:cookie-blocked', function(e){ console.log('[WALL] COOKIE:', e.detail.name); });
    D.addEventListener('wall:script-blocked', function(e){ console.log('[WALL] SCRIPT:', e.detail.src); });
  }

})(window, document, navigator);
