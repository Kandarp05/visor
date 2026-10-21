// feature_extractor/tier1_network.js
// Tier 1 extraction — runs in the background service worker.
// Registers webRequest/webNavigation listeners and writes directly
// into the session vector as events arrive.

import { createVector, updateVector, mutateVector } from './session_state.js';

// ── Helpers ───────────────────────────────────────────────────────────────

/**
 * Returns the registrable domain (eTLD+1 approximation using last two labels,
 * with leading 'www.' stripped), matching aitm-harness/crawler/extract.py.
 */
export function registrableDomain(hostname) {
  if (!hostname) return '';
  const parts = hostname.replace(/^www\./i, '').toLowerCase().split('.').filter(Boolean);
  return parts.length >= 2 ? parts.slice(-2).join('.') : hostname.toLowerCase();
}

export function getEtldPlusOne(hostname) {
  return registrableDomain(hostname);
}

// ── Origin-identity leakage (class-generic) ────────────────────────────────
//
// A reverse-proxy kit that forwards the origin's response headers verbatim leaks the
// authentic origin. Rewriting bodies is what phishlets normally do; rewriting headers
// is not. This is the strongest class-generic signal in the final feature set.

/** Relations that identify the site's own origin. `profile` is NOT identity-bearing. */
const IDENTITY_RELS = new Set([
  'canonical', 'shortlink', 'https://api.w.org/', 'alternate', 'edituri', 'hub',
]);

/** Headers whose value can name the origin. Others (alt-svc, server, via) cannot. */
const ORIGIN_REFERENCING_HEADERS = new Set([
  'link', 'location', 'content-location', 'x-pingback',
]);

/**
 * Split a header value on commas that are outside <> and outside quotes.
 * `Link: <a>; rel="x", <b>; rel="y"` -> ['<a>; rel="x"', '<b>; rel="y"']
 */
export function splitLinkHeader(value) {
  const parts = [];
  let depth = 0, inQuote = false, cur = '';
  for (const ch of String(value)) {
    if (ch === '<') depth++;
    else if (ch === '>') depth = Math.max(0, depth - 1);
    else if (ch === '"' && depth === 0) inQuote = !inQuote;
    if (ch === ',' && depth === 0 && !inQuote) { parts.push(cur); cur = ''; continue; }
    cur += ch;
  }
  if (cur.trim()) parts.push(cur);
  return parts;
}

/**
 * Extract the origin hosts named by identity-bearing Link relations.
 * Mirrors the dataset-side parser exactly — see aitm-harness/crawler/extract.py.
 *
 * @param {string[]} headerValues one entry per Link header, or a single joined value
 * @returns {string[]} distinct hostnames
 */
export function parseLinkIdentityHosts(headerValues) {
  const vals = Array.isArray(headerValues) ? headerValues : [headerValues];
  const hosts = new Set();
  for (const raw of vals) {
    if (!raw) continue;
    for (const part of splitLinkHeader(raw)) {
      const m = part.match(/<([^>]*)>\s*([\s\S]*)$/);
      if (!m) continue;
      const url = m[1].trim();
      const params = m[2] || '';
      const rels = new Set();
      const relRe = /rel\s*=\s*"?([^";]+)"?/gi;
      let rm;
      while ((rm = relRe.exec(params)) !== null) {
        for (const r of rm[1].split(/\s+/)) if (r) rels.add(r.toLowerCase());
      }
      if (![...rels].some((r) => IDENTITY_RELS.has(r))) continue;
      let h = '';
      try { h = new URL(url).hostname.toLowerCase(); } catch { h = ''; }
      if (h) hosts.add(h);
    }
  }
  return [...hosts];
}

/** Distinct foreign hosts named by any origin-referencing response header. */
export function parseForeignOriginHosts(headerEntries, pageHost) {
  const clean = (pageHost || '').toLowerCase();
  const hosts = new Set();
  for (const h of headerEntries) {
    const name = (h.name || '').toLowerCase();
    if (!ORIGIN_REFERENCING_HEADERS.has(name)) continue;
    const value = String(h.value || '');
    if (name === 'link') {
      for (const host of parseLinkIdentityHosts([value])) {
        if (host !== clean) hosts.add(host);
      }
      continue;
    }
    for (const m of value.matchAll(/https?:\/\/([a-z0-9.-]+)/gi)) {
      const host = m[1].toLowerCase();
      if (host !== clean) hosts.add(host);
    }
  }
  return [...hosts];
}

/**
 * Derive entry_path from the referrer and the observed redirect count, identically
 * on both sides.
 *   redirect_entry — this navigation was preceded by an HTTP redirect
 *   direct        — no referrer
 *   link_internal — referrer, same eTLD+1 as the page
 *   link_referrer — referrer, different eTLD+1
 */
export function deriveEntryPath(referer, pageHost, hopCount = 0) {
  if (hopCount > 0) return 'redirect_entry';
  if (!referer) return 'direct';
  let refHost = '';
  try { refHost = new URL(referer).hostname.toLowerCase(); } catch { refHost = ''; }
  if (!refHost) return 'direct';
  if (getEtldPlusOne(refHost) === getEtldPlusOne(pageHost)) return 'link_internal';
  return 'link_referrer';
}

function checkSetCookieMismatch(responseHeaders, pageHost) {
  if (!responseHeaders || !pageHost) return false;
  const cleanHost = pageHost.toLowerCase();
  for (const h of responseHeaders) {
    if ((h.name || '').toLowerCase() !== 'set-cookie') continue;
    const m = (h.value || '').match(/;\s*domain=([^;]+)/i);
    if (!m) continue;
    const cookieDomain = m[1].trim().replace(/^\./, '').toLowerCase();
    if (cookieDomain && cookieDomain !== cleanHost) {
      return true;
    }
  }
  return false;
}

/**
 * Robust HTTP protocol parser (Fixes D6).
 * Constrained to statusLine token regexes: /^HTTP\/2\b/, /^HTTP\/3\b/, /^HTTP\/1\.1\b/.
 * Protocols outside target vocabulary (e.g. HTTP/1.0) map to null.
 */
export function extractProtocol(details) {
  const sl = details.statusLine || '';
  if (/^HTTP\/2\b/i.test(sl) || /\bHTTP\/2(\.0)?\b/i.test(sl)) return 'h2';
  if (/^HTTP\/3\b/i.test(sl) || /\bHTTP\/3\b/i.test(sl)) return 'h3';
  if (/^HTTP\/1\.1\b/i.test(sl) || /\bHTTP\/1\.1\b/i.test(sl)) return 'http/1.1';
  return null;
}

/**
 * Classify a cookie according to the strict leading-dot contract (D1).
 * Host-only ⟺ domain has no leading dot and equals pageHost.
 * Parent/domain-scoped ⟺ domain starts with a dot or differs from pageHost.
 */
export function classifyCookie(cookie, pageHost) {
  const cleanHost = (pageHost || '').toLowerCase();
  const rawDomain = (cookie?.domain || '').toLowerCase();
  const cleanDomain = rawDomain.replace(/^\./, '');
  const isHostOnly = !rawDomain.startsWith('.') && (cleanDomain === cleanHost);
  const isParent = !isHostOnly;
  const isMismatch = (cleanDomain !== cleanHost) || rawDomain.startsWith('.');
  return { isHostOnly, isParent, isMismatch };
}

/**
 * Inspect cookie jar for the page (Fixes D1).
 * Note on filter: uses `url:` instead of `domain:`.
 * Chrome's `domain:` filter only matches equal or subdomains of the given host,
 * which excludes parent-domain cookies (e.g. `.phish.kandarpjindal.in` on
 * `wordpress.phish.kandarpjindal.in`). The `url:` filter retrieves all cookies
 * that would match a request to this URL (both host-only and parent-domain).
 */
async function refreshCookiesForHost(tabId, pageUrl, pageHost) {
  if (!chrome.cookies || !pageHost) return;
  try {
    const queryUrl = (pageUrl && pageUrl.startsWith('http')) ? pageUrl : `https://${pageHost}/`;
    const cookies = await chrome.cookies.getAll({ url: queryUrl });
    if (!Array.isArray(cookies)) return;

    let hasMismatch = false;
    let hostOnlyCount = 0;
    let parentDomainCount = 0;

    for (const c of cookies) {
      const { isHostOnly, isMismatch } = classifyCookie(c, pageHost);
      if (isHostOnly) {
        hostOnlyCount++;
      } else {
        parentDomainCount++;
      }
      if (isMismatch) {
        hasMismatch = true;
      }
    }

    const nCookies = hostOnlyCount + parentDomainCount;
    const parentRatio = nCookies > 0 ? (parentDomainCount / nCookies) : 0.0;

    await updateVector(tabId, {
      cookie_domain_mismatch: hasMismatch,
      n_cookies: nCookies,
      n_host_only_cookies: hostOnlyCount,
      n_parent_domain_cookies: parentDomainCount,
      parent_domain_ratio: parentRatio,
    });
  } catch (e) {
    console.warn('[Visor Tier1] chrome.cookies inspection failed:', e);
  }
}

// ── Event handlers ────────────────────────────────────────────────────────

function onBeforeNavigate(details) {
  if (details.frameId !== 0) return;
  console.log('[NAV] onBeforeNavigate', { tabId: details.tabId, url: details.url });
  createVector(details.tabId, details.url).catch(() => {});
}

function onCommitted(details) {
  if (details.frameId !== 0) return;
  console.log('[NAV] onCommitted', { tabId: details.tabId, url: details.url, transition: details.transitionType });
  updateVector(details.tabId, {
    url: details.url,
    transition_type: details.transitionType,
    transition_qualifiers: details.transitionQualifiers || [],
  }).catch(() => {});
}

function onCompleted(details) {
  if (details.frameId !== 0) return;
  console.log('[NAV] onCompleted', { tabId: details.tabId, url: details.url });
}

function onBeforeRedirect(details) {
  if (details.type !== 'main_frame') return;
  console.log('[NET] onBeforeRedirect', { tabId: details.tabId, url: details.url, redirectUrl: details.redirectUrl });

  const fromHost = (() => { try { return new URL(details.url).hostname; } catch { return ''; } })();
  const toHost   = (() => { try { return new URL(details.redirectUrl).hostname; } catch { return ''; } })();
  const fromEtld = getEtldPlusOne(fromHost);
  const toEtld   = getEtldPlusOne(toHost);
  const crossOrigin = (fromEtld && toEtld && fromEtld !== toEtld) ? 1 : 0;

  // Atomic update inside enqueue queue (Fixes C6 lost updates)
  mutateVector(details.tabId, (current) => {
    const navHops = (current.nav_redirect_hop_count ?? 0) + 1;
    const navCross = (current.nav_cross_origin_hop_count ?? 0) + crossOrigin;
    const sessHops = (current.session_redirect_hop_count ?? 0) + 1;
    const sessCross = (current.session_cross_origin_hop_count ?? 0) + crossOrigin;
    const chain = [...(current.redirect_chain ?? []), fromHost];

    return {
      ...current,
      nav_redirect_hop_count: navHops,
      redirect_hop_count: navHops,
      nav_cross_origin_hop_count: navCross,
      cross_origin_hop_count: navCross,
      session_redirect_hop_count: sessHops,
      session_cross_origin_hop_count: sessCross,
      ever_saw_cross_origin_hop: Boolean(current.ever_saw_cross_origin_hop || crossOrigin),
      redirect_chain: chain,
    };
  }).catch(() => {});
}

// ── Request stream listeners (D2) ─────────────────────────────────────────

function onBeforeRequest(details) {
  if (details.tabId < 0) return;
  const reqHost = (() => {
    try { return new URL(details.url).hostname.toLowerCase(); } catch { return ''; }
  })();
  if (!reqHost) return;

  mutateVector(details.tabId, (current) => {
    const pageHost = (() => {
      try { return new URL(current.url || details.url).hostname.toLowerCase(); } catch { return ''; }
    })();

    const nReqs = (current.n_requests || 0) + 1;
    const type = details.type || 'other';

    let doc = current.n_document || 0;
    let script = current.n_script || 0;
    let stylesheet = current.n_stylesheet || 0;
    let image = current.n_image || 0;
    let font = current.n_font || 0;
    let xhr = current.n_xhr || 0;
    let other = current.n_other || 0;

    if (type === 'main_frame' || type === 'sub_frame') doc++;
    else if (type === 'script') script++;
    else if (type === 'stylesheet') stylesheet++;
    else if (type === 'image') image++;
    else if (type === 'font') font++;
    else if (type === 'xmlhttprequest' || type === 'ping') xhr++;
    else other++;

    const hosts = new Set(current.req_hosts || []);
    hosts.add(reqHost);

    // A request is first-party if registrable(reqHost) === registrable(pageHost).
    // Note: In our current testbed corpus, third_party_ratio is degenerate (0.0 for all visits)
    // because our WordPress benign and phish twin sites serve no external third-party assets.
    // The metric is implemented here according to the general contract.
    const isFirstParty = pageHost ? (registrableDomain(reqHost) === registrableDomain(pageHost)) : true;
    const isSameHost = pageHost ? (reqHost === pageHost) : true;

    const thirdPartyReqs = (current.n_third_party_requests || 0) + (isFirstParty ? 0 : 1);
    const sameHostReqs = (current.n_same_host_requests || 0) + (isSameHost ? 1 : 0);

    return {
      ...current,
      n_requests: nReqs,
      n_document: doc,
      n_script: script,
      n_stylesheet: stylesheet,
      n_image: image,
      n_font: font,
      n_xhr: xhr,
      n_other: other,
      req_hosts: [...hosts],
      n_hosts: hosts.size,
      n_third_party_requests: thirdPartyReqs,
      n_same_host_requests: sameHostReqs,
      third_party_ratio: nReqs > 0 ? (thirdPartyReqs / nReqs) : 0.0,
      same_host_ratio: nReqs > 0 ? (sameHostReqs / nReqs) : 1.0,
    };
  }).catch(() => {});
}

function onWebRequestCompleted(details) {
  if (details.tabId < 0) return;
  if (details.fromCache) {
    mutateVector(details.tabId, (current) => {
      const cached = (current.n_cached || 0) + 1;
      const total = current.n_requests || 1;
      return {
        ...current,
        n_cached: cached,
        cache_ratio: cached / total,
      };
    }).catch(() => {});
  }
}

function onErrorOccurred(details) {
  if (details.tabId < 0) return;
  mutateVector(details.tabId, (current) => {
    return {
      ...current,
      n_failed: (current.n_failed || 0) + 1,
    };
  }).catch(() => {});
}

/**
 * Entry path — how the user arrived (class-generic).
 * A user who clicks a phishing link in an email arrives with a Referer; a user who
 * typed the URL does not. Derived identically on the dataset side.
 */
function onBeforeSendHeaders(details) {
  if (details.tabId < 0) return;
  if (details.type !== 'main_frame') return;

  let referer = '';
  for (const h of details.requestHeaders ?? []) {
    if ((h.name || '').toLowerCase() === 'referer') { referer = h.value || ''; break; }
  }
  const hasReferer = referer.length > 0;

  let pageHost = '';
  try { pageHost = new URL(details.url).hostname.toLowerCase(); } catch {}
  let referrerOrigin = '';
  if (hasReferer) {
    try { referrerOrigin = new URL(referer).origin.toLowerCase(); } catch {}
  }

  updateVector(details.tabId, {
    has_referer: hasReferer,
    referrer_origin: referrerOrigin,
  }).catch(() => {});

  // entry_path depends on the redirect count, which is only known once the
  // redirect has happened — read it inside the atomic mutate.
  mutateVector(details.tabId, (current) => ({
    ...current,
    entry_path: deriveEntryPath(
      hasReferer ? referer : '',
      pageHost,
      current.nav_redirect_hop_count ?? 0
    ),
  })).catch(() => {});
}

function processResponseHeaders(details) {
  const headers = details.responseHeaders ?? [];
  const reqUrl = details.url || '';
  const reqHost = (() => {
    try { return new URL(reqUrl).hostname; } catch { return ''; }
  })();

  // Inspect subresource & main_frame Set-Cookie for mismatch (Fixes C1 & C2)
  if (reqHost && checkSetCookieMismatch(headers, reqHost)) {
    updateVector(details.tabId, {
      set_cookie_domain_mismatch: true,
      cookie_domain_mismatch: true,
    }).catch(() => {});
  }

  // Main frame response sets page-level protocol, compression, and security headers
  if (details.type !== 'main_frame') return;

  const headerMap = {};
  for (const h of headers) {
    if (h.name) headerMap[h.name.toLowerCase()] = h.value;
  }

  const hsts = Boolean(headerMap['strict-transport-security']);
  const csp = Boolean(headerMap['content-security-policy']);
  const xfo = Boolean(headerMap['x-frame-options']);
  const xcto = Boolean(headerMap['x-content-type-options']);
  const referrer = Boolean(headerMap['referrer-policy']);
  const permissions = Boolean(headerMap['permissions-policy']);
  const coop = Boolean(headerMap['cross-origin-opener-policy']);
  const coep = Boolean(headerMap['cross-origin-embedder-policy']);
  const corp = Boolean(headerMap['cross-origin-resource-policy']);

  const headerScore = [hsts, csp, xfo, xcto, referrer, permissions].filter(Boolean).length;

  const contentEncoding = headerMap['content-encoding'] || '';
  const transferEncoding = headerMap['transfer-encoding'] || '';
  const isGzipped = Boolean(contentEncoding.toLowerCase().includes('gzip'));
  const isChunked = Boolean(transferEncoding.toLowerCase().includes('chunked'));
  const hasContentLength = 'content-length' in headerMap;

  // Connection reuse indicators (E1: proxy re-serialisation / connection termination)
  const connectionVal = (headerMap['connection'] || '').toLowerCase();
  const respConnHeader = 'connection' in headerMap;
  const respConnClose = respConnHeader && connectionVal.includes('close');

  let queryKeys = [];
  try {
    queryKeys = [...new URL(reqUrl).searchParams.keys()];
  } catch {}

  // ── Origin-identity leakage (class-generic) ────────────────────────────
  const linkValues = headers
    .filter((h) => (h.name || '').toLowerCase() === 'link')
    .map((h) => h.value);
  const identityHosts = parseLinkIdentityHosts(linkValues);
  const foreignIdentityHosts = identityHosts.filter(
    (h) => h !== reqHost.toLowerCase()
  );
  const identityMismatch = foreignIdentityHosts.length > 0;
  const identityMatchRatio = identityHosts.length
    ? (identityHosts.length - foreignIdentityHosts.length) / identityHosts.length
    : null;
  const foreignOriginHosts = parseForeignOriginHosts(headers, reqHost);

  updateVector(details.tabId, {
    url: reqUrl,
    has_hsts: hsts,
    has_csp: csp,
    hdr_hsts: hsts,
    hdr_csp: csp,
    hdr_xfo: xfo,
    hdr_xcto: xcto,
    hdr_referrer: referrer,
    hdr_permissions: permissions,
    hdr_coop: coop,
    hdr_coep: coep,
    hdr_corp: corp,
    header_score: headerScore,
    protocol: extractProtocol(details),
    is_gzipped: isGzipped,
    is_chunked: isChunked,
    has_content_length: hasContentLength,
    resp_connection_header: respConnHeader,
    resp_connection_close: respConnClose,
    content_encoding: contentEncoding,
    transfer_encoding: transferEncoding,
    url_query_keys: queryKeys,
    has_redirect_to: queryKeys.includes('redirect_to'),
    // class-generic: origin-identity leakage via response headers
    identity_host_mismatch_header: identityMismatch,
    n_identity_mismatch_header: foreignIdentityHosts.length,
    identity_match_ratio_header: identityMatchRatio,
    link_header_identity_hosts: identityHosts,
    n_foreign_origin_headers: foreignOriginHosts.length,
  }).catch(() => {});

  // Session-sticky: evidence observed on ANY page in this tab's session.
  if (identityMismatch) {
    updateVector(details.tabId, { ever_saw_identity_mismatch_header: true }).catch(() => {});
  }

  // Inspect existing cookie jar for this host using authoritative url filter (Fixes D1)
  if (reqHost) {
    refreshCookiesForHost(details.tabId, reqUrl, reqHost).catch(() => {});
  }
}

// ── Public ────────────────────────────────────────────────────────────────

export function init() {
  chrome.webNavigation.onBeforeNavigate.addListener(onBeforeNavigate);
  chrome.webNavigation.onCommitted.addListener(onCommitted);
  chrome.webNavigation.onCompleted.addListener(onCompleted);

  // Request-stream listeners (D2)
  chrome.webRequest.onBeforeRequest.addListener(
    onBeforeRequest,
    { urls: ['<all_urls>'] }
  );

  chrome.webRequest.onBeforeRedirect.addListener(
    onBeforeRedirect,
    { urls: ['<all_urls>'] }
  );

  // Registered ONLY on onHeadersReceived (Fixes C7 clobbering)
  chrome.webRequest.onHeadersReceived.addListener(
    processResponseHeaders,
    { urls: ['<all_urls>'] },
    ['responseHeaders', 'extraHeaders']
  );

  chrome.webRequest.onCompleted.addListener(
    onWebRequestCompleted,
    { urls: ['<all_urls>'] }
  );

  chrome.webRequest.onErrorOccurred.addListener(
    onErrorOccurred,
    { urls: ['<all_urls>'] }
  );

  // Referrer / entry path
  chrome.webRequest.onBeforeSendHeaders.addListener(
    onBeforeSendHeaders,
    { urls: ['<all_urls>'] },
    ['requestHeaders']
  );
}
