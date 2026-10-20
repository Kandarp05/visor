// feature_extractor/tier1_network.js
// Tier 1 extraction — runs in the background service worker.
// Registers webRequest/webNavigation listeners and writes directly
// into the session vector as events arrive.

import { createVector, updateVector, getVector } from './session_state.js';

// ── Domain-age cache (in-memory, cleared on SW restart) ──────────────────
const domainAgeCache = new Map(); // domain → { ageDays, expiresAt }
const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 h

// ── Helpers ───────────────────────────────────────────────────────────────

function registrableDomain(hostname) {
  if (!hostname) return '';
  const parts = hostname.replace(/^www\./, '').split('.');
  return parts.length >= 2 ? parts.slice(-2).join('.') : hostname;
}

function hasCookieDomainMismatch(responseHeaders, pageHost) {
  if (!responseHeaders || !pageHost) return false;
  for (const h of responseHeaders) {
    if (h.name.toLowerCase() !== 'set-cookie') continue;
    const m = h.value.match(/;\s*domain=([^;]+)/i);
    if (!m) continue;
    const cookieDomain = m[1].trim().replace(/^\./, '').toLowerCase();
    const cleanHost = pageHost.toLowerCase();
    if (cleanHost !== cookieDomain && !cleanHost.endsWith(`.${cookieDomain}`)) {
      return true;
    }
  }
  return false;
}

function extractProtocol(details, headerNames) {
  if (details.statusLine?.includes('HTTP/2')) return 'h2';
  if (details.statusLine?.includes('HTTP/3')) return 'h3';
  if (details.statusLine?.includes('HTTP/1.1')) return 'http/1.1';
  if (headerNames.includes('alt-svc')) return 'h2';
  if (details.url?.startsWith('https:')) return 'https';
  if (details.url?.startsWith('http:')) return 'http/1.1';
  return null;
}

async function lookupDomainAge(tabId, hostname) {
  const domain = registrableDomain(hostname);
  if (!domain) return;

  const cached = domainAgeCache.get(domain);
  if (cached && cached.expiresAt > Date.now()) {
    await updateVector(tabId, { domain_age_days: cached.ageDays });
    return;
  }

  let ageDays = null;

  // 1. crt.sh
  try {
    const resp = await fetch(
      `https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`,
      { signal: AbortSignal.timeout(6000) }
    );
    if (resp.ok) {
      const certs = await resp.json();
      if (Array.isArray(certs) && certs.length > 0) {
        const oldest = certs.reduce((a, b) =>
          new Date(a.not_before) < new Date(b.not_before) ? a : b
        );
        const age = Math.floor(
          (Date.now() - new Date(oldest.not_before).getTime()) / 86_400_000
        );
        if (age >= 0) ageDays = age;
      }
    }
  } catch {
    // fallback to RDAP
  }

  // 2. RDAP fallback
  if (ageDays === null) {
    try {
      const resp = await fetch(
        `https://rdap.org/domain/${encodeURIComponent(domain)}`,
        { signal: AbortSignal.timeout(6000) }
      );
      if (resp.ok) {
        const data = await resp.json();
        const regEvent = data.events?.find((e) => e.eventAction === 'registration');
        if (regEvent?.eventDate) {
          const age = Math.floor(
            (Date.now() - new Date(regEvent.eventDate).getTime()) / 86_400_000
          );
          if (age >= 0) ageDays = age;
        }
      }
    } catch {
      // both failed
    }
  }

  domainAgeCache.set(domain, { ageDays, expiresAt: Date.now() + CACHE_TTL_MS });
  await updateVector(tabId, { domain_age_days: ageDays });
}

// ── Event handlers ────────────────────────────────────────────────────────

function onBeforeNavigate(details) {
  if (details.frameId !== 0) return;
  console.log('[NAV] onBeforeNavigate', { tabId: details.tabId, url: details.url });
  createVector(details.tabId, details.url).catch(() => {});
}

function onCommitted(details) {
  if (details.frameId !== 0) return;
  console.log('[NAV] onCommitted', { tabId: details.tabId, url: details.url });
}

function onCompleted(details) {
  if (details.frameId !== 0) return;
  console.log('[NAV] onCompleted', { tabId: details.tabId, url: details.url });
}

async function onBeforeRedirect(details) {
  if (details.type !== 'main_frame') return;
  console.log('[NET] onBeforeRedirect', { tabId: details.tabId, url: details.url, redirectUrl: details.redirectUrl });
  const fromHost = (() => { try { return new URL(details.url).hostname; } catch { return ''; } })();
  const toHost   = (() => { try { return new URL(details.redirectUrl).hostname; } catch { return ''; } })();
  const crossOrigin = fromHost !== toHost ? 1 : 0;

  const current = await getVector(details.tabId);
  const hopCount = (current?.redirect_hop_count ?? 0) + 1;
  const crossCount = (current?.cross_origin_hop_count ?? 0) + crossOrigin;
  const chain = [...(current?.redirect_chain ?? []), fromHost];

  await updateVector(details.tabId, {
    redirect_hop_count: hopCount,
    cross_origin_hop_count: crossCount,
    redirect_chain: chain,
  });
}

function processResponseHeaders(details) {
  if (details.type !== 'main_frame') return;
  const headers = details.responseHeaders ?? [];
  const pageHost = (() => {
    try { return new URL(details.url).hostname; } catch { return ''; }
  })();

  const headerNames = headers.map((h) => h.name.toLowerCase());

  updateVector(details.tabId, {
    url: details.url,
    cookie_domain_mismatch: hasCookieDomainMismatch(headers, pageHost),
    has_hsts: headerNames.includes('strict-transport-security'),
    has_csp: headerNames.includes('content-security-policy'),
    protocol: extractProtocol(details, headerNames),
  }).catch(() => {});

  if (pageHost) lookupDomainAge(details.tabId, pageHost).catch(() => {});
}

// ── Public ────────────────────────────────────────────────────────────────

export function init() {
  chrome.webNavigation.onBeforeNavigate.addListener(onBeforeNavigate);
  chrome.webNavigation.onCommitted.addListener(onCommitted);
  chrome.webNavigation.onCompleted.addListener(onCompleted);

  chrome.webRequest.onBeforeRedirect.addListener(
    onBeforeRedirect,
    { urls: ['<all_urls>'] }
  );

  chrome.webRequest.onHeadersReceived.addListener(
    processResponseHeaders,
    { urls: ['<all_urls>'] },
    ['responseHeaders', 'extraHeaders']
  );

  chrome.webRequest.onCompleted.addListener(
    processResponseHeaders,
    { urls: ['<all_urls>'] },
    ['responseHeaders', 'extraHeaders']
  );
}
