// feature_extractor/tier1_network.js
// Tier 1 extraction — runs in the background service worker.
// Registers its own webRequest/webNavigation listeners and writes
// directly into the session vector as events arrive.
//
// Call init() once at service worker startup.

import { createVector, updateVector, getVector, deleteVector } from './session_state.js';

// ── Domain-age cache (in-memory, cleared on SW restart) ──────────────────
// Prevents hammering RDAP/crt.sh on repeated navigations to the same domain.
const domainAgeCache = new Map(); // domain → { ageDays, expiresAt }
const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 h

// ── Helpers ───────────────────────────────────────────────────────────────

/** Return "example.com" from "sub.example.com". Simple, not RFC-perfect. */
function registrableDomain(hostname) {
  const parts = hostname.replace(/^www\./, '').split('.');
  return parts.length >= 2 ? parts.slice(-2).join('.') : hostname;
}

/**
 * Parse the Set-Cookie response headers and return true if any cookie's
 * Domain attribute doesn't match the page host.
 */
function hasCookieDomainMismatch(responseHeaders, pageHost) {
  for (const h of responseHeaders) {
    if (h.name.toLowerCase() !== 'set-cookie') continue;
    const m = h.value.match(/;\s*domain=([^;]+)/i);
    if (!m) continue;
    const cookieDomain = m[1].trim().replace(/^\./, '').toLowerCase();
    const cleanHost = pageHost.toLowerCase();
    // Mismatch: page host is NOT the cookie domain, nor a subdomain of it
    if (cleanHost !== cookieDomain && !cleanHost.endsWith(`.${cookieDomain}`)) {
      return true;
    }
  }
  return false;
}

/** Guess h2 vs http/1.1 from the statusLine if available. */
function extractProtocol(details) {
  // webRequest doesn't reliably expose protocol; log what we can
  if (details.statusLine?.startsWith('HTTP/2')) return 'h2';
  if (details.statusLine?.startsWith('HTTP/1.1')) return 'http/1.1';
  return null;
}

/**
 * Async domain age lookup.
 * Tries crt.sh first (CORS-friendly, no auth), then RDAP as fallback.
 * Writes result into the session vector when it lands (may be after submit).
 */
async function lookupDomainAge(tabId, hostname) {
  const domain = registrableDomain(hostname);

  // Check cache
  const cached = domainAgeCache.get(domain);
  if (cached && cached.expiresAt > Date.now()) {
    await updateVector(tabId, { domain_age_days: cached.ageDays });
    return;
  }

  let ageDays = null;

  // ── Attempt 1: crt.sh (lists all certs, oldest gives earliest known date) ──
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
    // crt.sh failed — try RDAP
  }

  // ── Attempt 2: RDAP (if crt.sh gave nothing) ─────────────────────────────
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
      // Both lookups failed — domain_age_days stays null
    }
  }

  // Cache result (even null, to avoid retrying a known-failing domain)
  domainAgeCache.set(domain, { ageDays, expiresAt: Date.now() + CACHE_TTL_MS });

  // Write into vector (may no-op if tab was closed)
  await updateVector(tabId, { domain_age_days: ageDays });
}

// ── Event handlers ────────────────────────────────────────────────────────

function onBeforeNavigate(details) {
  if (details.frameId !== 0) return;
  // Create/reset vector for this top-level navigation
  createVector(details.tabId, details.url).catch(() => {});
}

async function onBeforeRedirect(details) {
  if (details.type !== 'main_frame') return;
  const fromHost = (() => { try { return new URL(details.url).hostname; } catch { return ''; } })();
  const toHost   = (() => { try { return new URL(details.redirectUrl).hostname; } catch { return ''; } })();
  const crossOrigin = fromHost !== toHost ? 1 : 0;

  const current = await getVector(details.tabId);
  if (!current) return;

  await updateVector(details.tabId, {
    redirect_hop_count: (current.redirect_hop_count ?? 0) + 1,
    cross_origin_hop_count: (current.cross_origin_hop_count ?? 0) + crossOrigin,
    redirect_chain: [...(current.redirect_chain ?? []), fromHost],
  });
}

function onCompleted(details) {
  if (details.type !== 'main_frame') return;

  const headers = details.responseHeaders ?? [];
  const pageHost = (() => {
    try { return new URL(details.url).hostname; } catch { return ''; }
  })();

  const headerNames = headers.map((h) => h.name.toLowerCase());

  updateVector(details.tabId, {
    cookie_domain_mismatch: hasCookieDomainMismatch(headers, pageHost),
    has_hsts: headerNames.includes('strict-transport-security'),
    has_csp: headerNames.includes('content-security-policy'),
    protocol: extractProtocol(details),
  }).catch(() => {});

  // Fire async domain-age lookup — result lands in the vector whenever ready
  if (pageHost) lookupDomainAge(details.tabId, pageHost).catch(() => {});
}

// ── Public ────────────────────────────────────────────────────────────────

/**
 * Register all Tier 1 listeners.
 * Must be called synchronously at service worker startup.
 */
export function init() {
  chrome.webNavigation.onBeforeNavigate.addListener(onBeforeNavigate);

  chrome.webRequest.onBeforeRedirect.addListener(
    onBeforeRedirect,
    { urls: ['<all_urls>'] }
  );

  chrome.webRequest.onCompleted.addListener(
    onCompleted,
    { urls: ['<all_urls>'] },
    ['responseHeaders', 'extraHeaders']
  );
}
