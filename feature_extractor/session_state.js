// feature_extractor/session_state.js
// Per-tab feature vector, stored in chrome.storage.session (memory-only,
// cleared on browser close — never written to disk).
//
// Key format:  "visor:tab:{tabId}"
// Lifecycle:   created on navigation start → updated incrementally
//              by Tier 1 and Tier 2 → read at gating moments → deleted
//              on tab close.

const PREFIX = 'visor:tab:';
const key = (tabId) => `${PREFIX}${tabId}`;

// In-memory queue to serialize async read-modify-write operations per tab.
// This prevents concurrent updates (e.g. webRequest + content script) from
// clobbering each other.
const tabQueues = new Map();

function enqueue(tabId, fn) {
  const prev = tabQueues.get(tabId) || Promise.resolve();
  const next = prev.then(fn, fn); // continue queue even if previous rejected
  tabQueues.set(tabId, next);
  return next;
}

/**
 * Canonical feature vector shape.
 * Every field starts at null/0/false.
 * Fields are filled progressively — a null means "not yet computed",
 * NOT "false". Callers must tolerate partial vectors.
 */
export function emptyVector(tabId, url = '') {
  return {
    tabId,
    url,
    createdAt: Date.now(),

    // ── Tier 1: network features (background service worker) ─────────────
    redirect_hop_count: 0,        // total number of HTTP redirects
    cross_origin_hop_count: 0,    // redirects where the host changed
    redirect_chain: [],           // ordered host list through redirect chain
    cookie_domain_mismatch: false,// any Set-Cookie domain attr ≠ page host
    has_hsts: null,               // Strict-Transport-Security present
    has_csp: null,                // Content-Security-Policy present
    protocol: null,               // "h2" | "http/1.1" | null
    domain_age_days: null,        // async RDAP/crt.sh lookup — arrives later

    // ── Tier 2: DOM features (content script) ────────────────────────────
    has_password_field: null,
    form_action_mismatch: null,   // form POSTs to a different origin
    has_iframe: null,
    iframe_overlap_viewport: null,// suspicious full-viewport iframe overlay
    identity_host_mismatch: null, // canonical/OG/JSON-LD host ≠ page host
  };
}

/**
 * Create or reset the vector for a tab when navigation starts.
 */
export function createVector(tabId, url) {
  return enqueue(tabId, async () => {
    const k = key(tabId);
    const stored = await chrome.storage.session.get(k);
    const existing = stored[k];

    // If navigating to the same URL or sub-resource in the same page,
    // preserve already computed features rather than wiping them.
    if (existing && existing.url === url) {
      return existing;
    }

    const v = emptyVector(tabId, url);
    await chrome.storage.session.set({ [k]: v });
    return v;
  });
}

/**
 * Merge a patch object into the existing vector.
 * Serialized per tabId so updates never overwrite each other.
 */
export function updateVector(tabId, patch) {
  return enqueue(tabId, async () => {
    if (!patch || typeof patch !== 'object') return null;
    const k = key(tabId);
    const stored = await chrome.storage.session.get(k);
    // If vector doesn't exist yet, create a baseline rather than dropping data
    const current = stored[k] || emptyVector(tabId, patch.url || '');
    const updated = { ...current, ...patch };
    await chrome.storage.session.set({ [k]: updated });
    return updated;
  });
}

/** Read the current vector for a tab. Returns null if none exists. */
export async function getVector(tabId) {
  const stored = await chrome.storage.session.get(key(tabId));
  return stored[key(tabId)] ?? null;
}

/** Delete the vector for a tab (called on tab close). */
export function deleteVector(tabId) {
  tabQueues.delete(tabId);
  return chrome.storage.session.remove(key(tabId));
}
