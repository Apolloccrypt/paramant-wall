// PARAMANT WALL — BUILT-IN TRACKER DATABASE
// Gegenereerd op basis van top-853 tracker lijst
// Categorieën: advertising, analytics, social, consent, utilities, hosting
// Acties: block, strip (cookies strippen + IP anonimiseren), allow

const BUILT_IN_TRACKERS = {

  // ══════════════════════════════════════════════
  // ANALYTICS
  // ══════════════════════════════════════════════
  ga4: {
    name: 'Google Analytics 4',
    vendor: 'Google',
    category: 'analytics',
    defaultAction: 'strip',
    domains: ['google-analytics.com', 'analytics.google.com', 'region1.google-analytics.com', 'googletagmanager.com'],
    cookies: ['_ga', '_ga_', '_gid', '_gat', '_gat_UA', '_dc_gtm_', '__utma', '__utmb', '__utmc', '__utmz', '__utmt'],
    stripFields: ['client_id', 'user_id', 'ip_override', 'user_properties'],
  },
  ga_signals: {
    name: 'Google Analytics (Signals)',
    vendor: 'Google',
    category: 'analytics',
    defaultAction: 'strip',
    domains: ['google-analytics.com/g/collect'],
    cookies: ['_ga', '_gid'],
    stripFields: ['client_id', 'user_id'],
  },
  mixpanel: {
    name: 'Mixpanel',
    vendor: 'Mixpanel',
    category: 'analytics',
    defaultAction: 'block',
    domains: ['api.mixpanel.com', 'cdn.mxpnl.com'],
    cookies: ['mp_', '__mp_opt_in_out_'],
    stripFields: ['distinct_id', '$user_id'],
  },
  amplitude: {
    name: 'Amplitude',
    vendor: 'Amplitude',
    category: 'analytics',
    defaultAction: 'block',
    domains: ['api.amplitude.com', 'api2.amplitude.com'],
    cookies: ['amplitude_id', 'amplitude_unsent'],
    stripFields: ['device_id', 'user_id'],
  },
  segment: {
    name: 'Segment',
    vendor: 'Twilio',
    category: 'analytics',
    defaultAction: 'block',
    domains: ['api.segment.io', 'cdn.segment.com', 'analytics.js'],
    cookies: ['ajs_user_id', 'ajs_anonymous_id'],
    stripFields: ['userId', 'anonymousId'],
  },
  hotjar: {
    name: 'Hotjar',
    vendor: 'Hotjar',
    category: 'analytics',
    defaultAction: 'block',
    domains: ['static.hotjar.com', 'vars.hotjar.com', 'vc.hotjar.io', 'ask.hotjar.io'],
    cookies: ['_hjid', '_hjSession', '_hjTLDTest', '_hjAbsoluteSessionInProgress', '_hjIncludedInPageviewSample', '_hjFirstSeen'],
    stripFields: [],
  },
  chartbeat: {
    name: 'Chartbeat',
    vendor: 'Chartbeat',
    category: 'analytics',
    defaultAction: 'block',
    domains: ['static.chartbeat.com', 'ping.chartbeat.net'],
    cookies: ['_cb', '_cb_ls', '_chartbeat2', '_cb_svref'],
    stripFields: [],
  },
  comscore: {
    name: 'Comscore / ScoreCard Research',
    vendor: 'comScore',
    category: 'analytics',
    defaultAction: 'block',
    domains: ['scorecardresearch.com', 'beacon.scorecardresearch.com'],
    cookies: ['UID', 'UIDR'],
    stripFields: [],
  },
  microsoft_clarity: {
    name: 'Microsoft Clarity',
    vendor: 'Microsoft',
    category: 'analytics',
    defaultAction: 'block',
    domains: ['clarity.ms', 'www.clarity.ms'],
    cookies: ['_clck', '_clsk', 'CLID', 'ANONCHK'],
    stripFields: [],
  },
  new_relic: {
    name: 'New Relic',
    vendor: 'New Relic',
    category: 'analytics',
    defaultAction: 'block',
    domains: ['bam.nr-data.net', 'js-agent.newrelic.com'],
    cookies: [],
    stripFields: [],
  },
  datadog: {
    name: 'Datadog',
    vendor: 'Datadog',
    category: 'analytics',
    defaultAction: 'block',
    domains: ['browser-intake-datadoghq.com', 'browser-intake-datadoghq.eu'],
    cookies: ['_dd_s'],
    stripFields: [],
  },
  fullstory: {
    name: 'FullStory',
    vendor: 'FullStory',
    category: 'analytics',
    defaultAction: 'block',
    domains: ['fullstory.com', 'rs.fullstory.com', 'edge.fullstory.com'],
    cookies: ['fs_uid', 'fs_lua'],
    stripFields: [],
  },
  quantcast: {
    name: 'Quantcast',
    vendor: 'Quantcast',
    category: 'analytics',
    defaultAction: 'block',
    domains: ['quantserve.com', 'pixel.quantserve.com'],
    cookies: ['mc', '__qca'],
    stripFields: [],
  },
  parsely: {
    name: 'Parse.ly',
    vendor: 'Parse.ly',
    category: 'analytics',
    defaultAction: 'block',
    domains: ['parsely.com', 'p1.parsely.com', 'srv.pixel.parsely.com'],
    cookies: ['_parsely_visitor', '_parsely_session'],
    stripFields: [],
  },
  yandex_metrika: {
    name: 'Yandex Metrika',
    vendor: 'Yandex',
    category: 'analytics',
    defaultAction: 'block',
    domains: ['mc.yandex.ru', 'mc.yandex.com', 'an.yandex.ru'],
    cookies: ['_ym_uid', '_ym_d', '_ym_isad', '_ym_visorc', 'yabs-sid'],
    stripFields: [],
  },
  piano_analytics: {
    name: 'Piano Analytics (AT Internet)',
    vendor: 'Piano Software',
    category: 'analytics',
    defaultAction: 'block',
    domains: ['piano.io', 'atinternet.com', 'xiti.com'],
    cookies: ['atuserid', 'atidvisitor'],
    stripFields: [],
  },
  mparticle: {
    name: 'mParticle',
    vendor: 'mParticle',
    category: 'analytics',
    defaultAction: 'block',
    domains: ['mparticle.com', 'jssdks.mparticle.com'],
    cookies: ['mprtcl-api', 'mprtcl-v4'],
    stripFields: [],
  },
  heap: {
    name: 'Heap Analytics',
    vendor: 'Contentsquare',
    category: 'analytics',
    defaultAction: 'block',
    domains: ['heapanalytics.com', 'cdn.heapanalytics.com'],
    cookies: ['_hp2_id', '_hp2_ses_props'],
    stripFields: [],
  },
  pendo: {
    name: 'Pendo',
    vendor: 'Pendo',
    category: 'analytics',
    defaultAction: 'block',
    domains: ['pendo.io', 'cdn.pendo.io', 'data.pendo.io'],
    cookies: [],
    stripFields: [],
  },
  wordpress_stats: {
    name: 'WordPress Stats / Jetpack',
    vendor: 'Automattic',
    category: 'analytics',
    defaultAction: 'block',
    domains: ['stats.wp.com', 'pixel.wp.com'],
    cookies: [],
    stripFields: [],
  },

  // ══════════════════════════════════════════════
  // ADVERTISING
  // ══════════════════════════════════════════════
  meta_pixel: {
    name: 'Meta Pixel (Facebook/Instagram)',
    vendor: 'Meta',
    category: 'advertising',
    defaultAction: 'block',
    domains: ['connect.facebook.net', 'www.facebook.com/tr', 'facebook.com/tr', 'graph.facebook.com'],
    cookies: ['_fbp', '_fbc', 'fr', 'datr', 'sb', 'xs'],
    stripFields: ['fbp', 'fbc', 'external_id'],
  },
  google_ads: {
    name: 'Google Ads / DoubleClick',
    vendor: 'Google',
    category: 'advertising',
    defaultAction: 'block',
    domains: ['googleads.g.doubleclick.net', 'www.googleadservices.com', 'pagead2.googlesyndication.com', 'tpc.googlesyndication.com', 'adservice.google.com'],
    cookies: ['IDE', 'ANID', '__gads', '__gpi', 'NID', 'AID', 'DSID', 'FLC', 'RUL'],
    stripFields: [],
  },
  tiktok: {
    name: 'TikTok Pixel / Analytics',
    vendor: 'ByteDance',
    category: 'advertising',
    defaultAction: 'block',
    domains: ['analytics.tiktok.com', 'ads.tiktok.com', 'business.tiktok.com'],
    cookies: ['_ttp', '_tt_enable_cookie', '_tt_uid'],
    stripFields: [],
  },
  linkedin_ads: {
    name: 'LinkedIn Insight Tag',
    vendor: 'Microsoft',
    category: 'advertising',
    defaultAction: 'block',
    domains: ['snap.licdn.com', 'px.ads.linkedin.com', 'dc.ads.linkedin.com'],
    cookies: ['li_sugr', 'bcookie', 'li_gc', 'UserMatchHistory', 'AnalyticsSyncHistory', 'lms_ads', 'lms_analytics'],
    stripFields: [],
  },
  microsoft_ads: {
    name: 'Microsoft Advertising (Bing Ads)',
    vendor: 'Microsoft',
    category: 'advertising',
    defaultAction: 'block',
    domains: ['bat.bing.com', 'universal.bing.com'],
    cookies: ['_uetsid', '_uetvid', 'MR', 'MUID'],
    stripFields: [],
  },
  criteo: {
    name: 'Criteo',
    vendor: 'Criteo',
    category: 'advertising',
    defaultAction: 'block',
    domains: ['static.criteo.net', 'dis.criteo.com', 'gum.criteo.com'],
    cookies: ['uid', 'optout', 'cto_bundle', 'cto_optout'],
    stripFields: [],
  },
  taboola: {
    name: 'Taboola',
    vendor: 'Taboola',
    category: 'advertising',
    defaultAction: 'block',
    domains: ['trc.taboola.com', 'cdn.taboola.com', 'nr-data.taboola.com'],
    cookies: ['taboola_session_id', 'trc_cookie_storage'],
    stripFields: [],
  },
  outbrain: {
    name: 'Outbrain',
    vendor: 'Outbrain',
    category: 'advertising',
    defaultAction: 'block',
    domains: ['widgets.outbrain.com', 'log.outbrain.com', 'amplify.outbrain.com'],
    cookies: ['obuid'],
    stripFields: [],
  },
  tradedesk: {
    name: 'The Trade Desk',
    vendor: 'The Trade Desk',
    category: 'advertising',
    defaultAction: 'block',
    domains: ['js.adsrvr.org', 'match.adsrvr.org', 'pixel.adsrvr.org'],
    cookies: ['TDID', 'TDCPM', 'TTDOptOut'],
    stripFields: [],
  },
  amazon_ads: {
    name: 'Amazon Advertising',
    vendor: 'Amazon',
    category: 'advertising',
    defaultAction: 'block',
    domains: ['amazon-adsystem.com', 'aax.amazon-adsystem.com', 's.amazon-adsystem.com'],
    cookies: ['ad-id', 'ad-privacy', 'x-wl-uid'],
    stripFields: [],
  },
  pinterest: {
    name: 'Pinterest Tag',
    vendor: 'Pinterest',
    category: 'advertising',
    defaultAction: 'block',
    domains: ['ct.pinterest.com', 'pintrk', 's.pinimg.com'],
    cookies: ['_pinterest_sess', '_pinterest_ct_ua', 'csrftoken'],
    stripFields: [],
  },
  snapchat: {
    name: 'Snapchat Pixel',
    vendor: 'Snap',
    category: 'advertising',
    defaultAction: 'block',
    domains: ['tr.snapchat.com', 'sc-static.net'],
    cookies: ['_scid', '_scid_r', '_sctr'],
    stripFields: [],
  },
  reddit_ads: {
    name: 'Reddit Pixel',
    vendor: 'Reddit',
    category: 'advertising',
    defaultAction: 'block',
    domains: ['alb.reddit.com', 'rp.reddit.com', 'events.reddit.com'],
    cookies: ['reddaid'],
    stripFields: [],
  },
  adobe_audience: {
    name: 'Adobe Audience Manager',
    vendor: 'Adobe',
    category: 'advertising',
    defaultAction: 'block',
    domains: ['demdex.net', 'omtrdc.net', '2o7.net'],
    cookies: ['demdex', 'dpm', 's_ecid'],
    stripFields: [],
  },
  pubmatic: {
    name: 'PubMatic',
    vendor: 'PubMatic',
    category: 'advertising',
    defaultAction: 'block',
    domains: ['image6.pubmatic.com', 'image8.pubmatic.com', 'ads.pubmatic.com'],
    cookies: ['KRTBCOOKIE_', 'PugT'],
    stripFields: [],
  },
  magnite: {
    name: 'Magnite (Rubicon)',
    vendor: 'Magnite',
    category: 'advertising',
    defaultAction: 'block',
    domains: ['fastlane.rubiconproject.com', 'tap.rubiconproject.com', 'eus.rubiconproject.com'],
    cookies: ['rpx', 'put_'],
    stripFields: [],
  },
  appnexus: {
    name: 'AppNexus / Xandr (Microsoft)',
    vendor: 'Microsoft',
    category: 'advertising',
    defaultAction: 'block',
    domains: ['ib.adnxs.com', 'secure.adnxs.com', 'acdn.adnxs.com'],
    cookies: ['uuid2', 'anj', 'sess'],
    stripFields: [],
  },
  openx: {
    name: 'OpenX',
    vendor: 'OpenX',
    category: 'advertising',
    defaultAction: 'block',
    domains: ['u.openx.net', 'd.openx.net', 'i.openx.net'],
    cookies: ['i', 'pd'],
    stripFields: [],
  },

  // ══════════════════════════════════════════════
  // SOCIAL MEDIA
  // ══════════════════════════════════════════════
  twitter_x: {
    name: 'X (Twitter) Pixel',
    vendor: 'X Corp.',
    category: 'social',
    defaultAction: 'block',
    domains: ['static.ads-twitter.com', 't.co', 'analytics.twitter.com', 'ads-api.twitter.com'],
    cookies: ['guest_id', 'guest_id_ads', 'guest_id_marketing', 'personalization_id', 'ct0'],
    stripFields: [],
  },

  // ══════════════════════════════════════════════
  // CONSENT MANAGEMENT PLATFORMS
  // ══════════════════════════════════════════════
  onetrust: {
    name: 'OneTrust',
    vendor: 'OneTrust',
    category: 'consent',
    defaultAction: 'allow',
    domains: ['cdn.cookielaw.org', 'geolocation.onetrust.com', 'privacyportal.onetrust.com'],
    cookies: ['OptanonConsent', 'OptanonAlertBoxClosed', 'eupubconsent-v2'],
    stripFields: [],
  },
  cookiebot: {
    name: 'Cookiebot',
    vendor: 'Usercentrics',
    category: 'consent',
    defaultAction: 'allow',
    domains: ['consent.cookiebot.com', 'consentcdn.cookiebot.com'],
    cookies: ['CookieConsent'],
    stripFields: [],
  },
  didomi: {
    name: 'Didomi',
    vendor: 'Didomi',
    category: 'consent',
    defaultAction: 'allow',
    domains: ['sdk.privacy-center.org', 'consent.privacy-center.org'],
    cookies: ['euconsent-v2', 'didomi_token'],
    stripFields: [],
  },

  // ══════════════════════════════════════════════
  // UTILITIES / PERF MONITORING
  // ══════════════════════════════════════════════
  sentry: {
    name: 'Sentry',
    vendor: 'Sentry',
    category: 'utilities',
    defaultAction: 'allow',
    domains: ['sentry.io', 'o0.ingest.sentry.io', 'browser.sentry-cdn.com'],
    cookies: [],
    stripFields: [],
  },
  cloudflare_insights: {
    name: 'Cloudflare Web Analytics',
    vendor: 'Cloudflare',
    category: 'analytics',
    defaultAction: 'allow',
    domains: ['static.cloudflareinsights.com', 'cloudflareinsights.com'],
    cookies: [],
    stripFields: [],
  },
  intercom: {
    name: 'Intercom',
    vendor: 'Intercom',
    category: 'utilities',
    defaultAction: 'strip',
    domains: ['js.intercomcdn.com', 'api.intercom.io', 'widget.intercom.io'],
    cookies: ['intercom-id-', 'intercom-session-', 'intercom-device-id-'],
    stripFields: ['user_id', 'email', 'name'],
  },
  hubspot: {
    name: 'HubSpot',
    vendor: 'HubSpot',
    category: 'analytics',
    defaultAction: 'block',
    domains: ['js.hs-scripts.com', 'js.hsforms.net', 'track.hubspot.com', 'api.hubapi.com'],
    cookies: ['hubspotutk', '__hstc', '__hssrc', '__hssc', '__hsfp'],
    stripFields: [],
  },
  optimizely: {
    name: 'Optimizely',
    vendor: 'Optimizely',
    category: 'utilities',
    defaultAction: 'strip',
    domains: ['cdn.optimizely.com', 'logx.optimizely.com'],
    cookies: ['optimizelyBuckets', 'optimizelyEndUserId', 'optimizelySegments'],
    stripFields: [],
  },

  // ══════════════════════════════════════════════
  // CUSTOMER INTERACTION / CHAT
  // ══════════════════════════════════════════════
  zendesk: {
    name: 'Zendesk',
    vendor: 'Zendesk',
    category: 'utilities',
    defaultAction: 'allow',
    domains: ['ekr.zdassets.com', 'static.zdassets.com'],
    cookies: ['ZD-', '__zlcid', '__zl'],
    stripFields: [],
  },
};

// ══════════════════════════════════════════════
// TEMPLATES — voorgedefinieerde profielen
// ══════════════════════════════════════════════
const TEMPLATES = {
  'ultra-streng': {
    label: 'Ultra Streng',
    description: 'Blokkeert alles behalve functionele scripts. Maximale privacy.',
    overrides: {
      // Alle advertising: block
      meta_pixel: 'block', google_ads: 'block', tiktok: 'block',
      linkedin_ads: 'block', microsoft_ads: 'block', criteo: 'block',
      taboola: 'block', outbrain: 'block', tradedesk: 'block',
      amazon_ads: 'block', pinterest: 'block', snapchat: 'block',
      reddit_ads: 'block', adobe_audience: 'block', pubmatic: 'block',
      magnite: 'block', appnexus: 'block', openx: 'block', twitter_x: 'block',
      // Analytics: strip (niet block — analytics mogen nog werken)
      ga4: 'strip', ga_signals: 'strip',
      // Zware analytics: block
      hotjar: 'block', fullstory: 'block', microsoft_clarity: 'block',
      mixpanel: 'block', amplitude: 'block', segment: 'block',
      chartbeat: 'block', comscore: 'block', yandex_metrika: 'block',
      heap: 'block', pendo: 'block',
      // Consent: allow
      onetrust: 'allow', cookiebot: 'allow', didomi: 'allow',
    }
  },
  'basis-analytics': {
    label: 'Basis Analytics',
    description: 'GA4 en basis analytics doorgelaten. Advertising geblokkeerd.',
    overrides: {
      ga4: 'strip', ga_signals: 'strip',
      meta_pixel: 'block', google_ads: 'block', tiktok: 'block',
      hotjar: 'strip', fullstory: 'block', microsoft_clarity: 'strip',
    }
  },
  'marketing-light': {
    label: 'Marketing Light',
    description: 'GA4 + Meta + retargeting doorgelaten maar cookies gestript.',
    overrides: {
      ga4: 'strip', meta_pixel: 'strip', google_ads: 'strip',
      hotjar: 'block', fullstory: 'block',
      tiktok: 'block', yandex_metrika: 'block',
    }
  },
  'custom': {
    label: 'Aangepast',
    description: 'Pas elke tracker individueel aan.',
    overrides: {}
  }
};

// ══════════════════════════════════════════════
// HELPER: resolve effectieve actie
// ══════════════════════════════════════════════
function getTrackerAction(url, template, customRules) {
  const urlLower = url.toLowerCase();

  // 1. Custom rules van klant (hoogste prioriteit)
  if (customRules && customRules.length) {
    for (const rule of customRules) {
      if (rule.domain && urlLower.includes(rule.domain.toLowerCase())) {
        return { tracker: rule.domain, action: rule.action, custom: true };
      }
    }
  }

  // 2. Built-in trackers
  const tpl = TEMPLATES[template] || TEMPLATES['ultra-streng'];
  for (const [key, tracker] of Object.entries(BUILT_IN_TRACKERS)) {
    for (const domain of tracker.domains) {
      if (urlLower.includes(domain.toLowerCase())) {
        // Template override heeft prioriteit
        const action = (tpl.overrides && tpl.overrides[key]) || tracker.defaultAction;
        return {
          tracker: key,
          name: tracker.name,
          category: tracker.category,
          action,
          cookies: tracker.cookies,
          stripFields: tracker.stripFields,
        };
      }
    }
  }

  return null;
}

// ══════════════════════════════════════════════
// TRACKER CATEGORIEËN voor de feed/UI
// ══════════════════════════════════════════════
const TRACKER_CATEGORIES = {
  advertising:  { label: 'Advertising',        color: '#ef4444', default: 'block' },
  analytics:    { label: 'Site Analytics',      color: '#f5c400', default: 'strip' },
  social:       { label: 'Social Media',        color: '#60a5fa', default: 'block' },
  consent:      { label: 'Consent Management',  color: '#00ff9d', default: 'allow' },
  utilities:    { label: 'Utilities',           color: '#a78bfa', default: 'allow' },
  hosting:      { label: 'Hosting/CDN',         color: '#8a8e98', default: 'allow' },
};

module.exports = { BUILT_IN_TRACKERS, TEMPLATES, TRACKER_CATEGORIES, getTrackerAction };
