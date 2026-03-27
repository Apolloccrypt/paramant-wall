/**
 * PARAMANT WALL — snippet.js v3.3.0
 * Drop-in privacy interceptor (geen forwarding tenzij expliciet toegestaan)
 * Onderschept: fetch, XMLHttpRequest, sendBeacon, document.cookie
 * Gebruikt: <script src="https://wall.paramant.app/snippet.js?k=wk_..."></script>
 */
(function(W, D, N) {
  'use strict';

  var BASE_URL = 'https://wall.paramant.app';
  var API_KEY  = (function() {
    var scripts = D.querySelectorAll('script[src*="snippet.js"]');
    for (var i = 0; i < scripts.length; i++) {
      var m = (scripts[i].src || '').match(/[?&]k=([^&]+)/);
      if (m) return m[1];
    }
    return '';
  })();

  if (!API_KEY) {
    if (W.location.hostname === 'localhost' || W.location.hostname === '127.0.0.1') {
      console.warn('[PARAMANT WALL] Geen API key gevonden. Voeg ?k=wk_... toe aan de script src.');
    }
    return;
  }

  var INTERCEPT_PATTERNS = [
    /google-analytics\.com\/g\/collect/,/analytics\.google\.com\/g\/collect/,
    /region\d*\.google-analytics\.com/,/googletagmanager\.com\/gtm\.js/,
    /googletagmanager\.com\/gtag\/js/,/connect\.facebook\.net/,
    /facebook\.com\/tr/,/graph\.facebook\.com/,
    /googleads\.g\.doubleclick\.net/,/pagead2\.googlesyndication\.com/,
    /www\.googleadservices\.com/,/analytics\.tiktok\.com/,
    /ads\.tiktok\.com/,/snap\.licdn\.com/,/px\.ads\.linkedin\.com/,
    /dc\.ads\.linkedin\.com/,/bat\.bing\.com/,/universal\.bing\.com/,
    /static\.hotjar\.com/,/vars\.hotjar\.com/,/vc\.hotjar\.io/,
    /clarity\.ms/,/rs\.fullstory\.com/,/edge\.fullstory\.com/,
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
    /bam\.nr-data\.net/,/browser-intake-datadoghq\.com/,
    /amazon-adsystem\.com/,/secure\.adnxs\.com/,/ib\.adnxs\.com/,
  ];

  function shouldIntercept(url) {
    if (!url) return false;
    var u = String(url);
    if (u.indexOf(BASE_URL) === 0) return false;
    for (var i = 0; i < INTERCEPT_PATTERNS.length; i++) {
      if (INTERCEPT_PATTERNS[i].test(u)) return true;
    }
    return false;
  }

  function buildWallUrl() {
    return BASE_URL + '/proxy/generic?_wk=' + encodeURIComponent(API_KEY);
  }

  // 1. fetch
  var _origFetch = W.fetch;
  W.fetch = function(input, init) {
    var url = typeof input === 'string' ? input : (input && input.url ? input.url : String(input));
    if (!shouldIntercept(url)) return _origFetch.apply(this, arguments);
    var wallUrl = buildWallUrl();
    var newInit = {};
    if (init) { for (var k in init) { if (Object.prototype.hasOwnProperty.call(init, k)) newInit[k] = init[k]; } }
    newInit.headers = newInit.headers || {};
    if (typeof newInit.headers === 'object' && !newInit.headers.append) {
      newInit.headers['x-wall-key'] = API_KEY;
      delete newInit.headers['cookie'];
    }
    return _origFetch.call(W, wallUrl, newInit);
  };

  // 2. XHR
  var XHR = W.XMLHttpRequest;
  var _open = XHR.prototype.open, _send = XHR.prototype.send, _setHdr = XHR.prototype.setRequestHeader;
  XHR.prototype.open = function(method, url, async, user, pass) {
    this._wallOrig = url;
    if (shouldIntercept(url)) { this._wallActive = true; return _open.call(this, method, buildWallUrl(), async !== undefined ? async : true, user, pass); }
    return _open.apply(this, arguments);
  };
  XHR.prototype.setRequestHeader = function(name, value) {
    if (this._wallActive) { var n = (name||'').toLowerCase(); if (n === 'cookie' || n === 'referer') return; }
    return _setHdr.apply(this, arguments);
  };
  XHR.prototype.send = function(body) {
    if (this._wallActive) { try { _setHdr.call(this, 'x-wall-key', API_KEY); } catch(e) {} }
    return _send.apply(this, arguments);
  };

  // 3. sendBeacon
  if (N && N.sendBeacon) {
    var _origBeacon = N.sendBeacon.bind(N);
    N.sendBeacon = function(url, data) {
      if (!shouldIntercept(url)) return _origBeacon(url, data);
      var wallUrl = buildWallUrl();
      try { return _origBeacon(wallUrl, data); } catch(e) {
        _origFetch.call(W, wallUrl, { method:'POST', body:data, keepalive:true, headers:{'x-wall-key':API_KEY} }).catch(function(){});
        return true;
      }
    };
  }

  // 4. Cookie blocking
  var BLOCKED = ['_ga','_gid','_gat','_dc_gtm_','_fbp','_fbc','fr','_ttp','__utma','__utmb','__utmc','__utmz','_hjid','_hjSession','mp_','ajs_','li_sugr','bcookie','MUID','_uetsid','_uetvid','IDE','ANID','NID','cto_bundle','obuid','TDID','_scid','_pinterest_sess'];
  var cDesc = Object.getOwnPropertyDescriptor(D, 'cookie') || Object.getOwnPropertyDescriptor(Object.getPrototypeOf(D), 'cookie');
  if (cDesc && cDesc.set) {
    var _origSet = cDesc.set;
    Object.defineProperty(D, 'cookie', {
      get: cDesc.get,
      set: function(val) {
        var name = (val||'').split('=')[0].trim();
        for (var i = 0; i < BLOCKED.length; i++) { if (name.indexOf(BLOCKED[i]) === 0) return; }
        return _origSet.call(D, val);
      },
      configurable: true
    });
  }

  // 5. Status
  W.__WALL__ = { active:true, version:'3.3.0', key:API_KEY.slice(0,8)+'...', patterns:INTERCEPT_PATTERNS.length };
  if (W.location.hostname === 'localhost' || W.location.hostname === '127.0.0.1') {
    console.log('%c[PARAMANT WALL] v3.3.0 actief — '+INTERCEPT_PATTERNS.length+' patronen', 'color:#00ff9d;background:#0c0e10;padding:2px 6px;font-weight:bold');
  }

})(window, document, navigator);
