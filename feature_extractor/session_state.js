// feature_extractor/session_state.js
// Per-tab feature vector, stored in chrome.storage.session (memory-only,
// cleared on browser close — never written to disk).
//
// Key format:  "visor:tab:{tabId}"
// Lifecycle:   created on navigation start → updated incrementally
//              by Tier 1 and Tier 2 → read at gating moments → deleted
//              on tab close or navigation away.

const PREFIX = 'visor:tab:';
const key = (tabId) => `${PREFIX}${tabId}`;

/**
 * Canonical feature vector shape.
 * Every field starts at null/0/false.
 * Fields are filled progressively — a null means "not yet computed",
 * NOT "false". Callers must tolerate partial vectors.
 */
export function emptyVector(tabId, url) {
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

/** Create and persist a fresh vector for a tab/navigation. */
export async function createVector(tabId, url) {
  const v = emptyVector(tabId, url);
  await chrome.storage.session.set({ [key(tabId)]: v });
  return v;
}

/**
 * Merge a patch object into the existing vector.
 * Returns the updated vector, or null if the tab was already closed.
 */
export async function updateVector(tabId, patch) {
  const k = key(tabId);
  const stored = await chrome.storage.session.get(k);
  const current = stored[k];
  if (!current) return null;         // tab closed between events — safe to ignore
  const updated = { ...current, ...patch };
  await chrome.storage.session.set({ [k]: updated });
  return updated;
}

/** Read the current vector for a tab. Returns null if none exists. */
export async function getVector(tabId) {
  const stored = await chrome.storage.session.get(key(tabId));
  return stored[key(tabId)] ?? null;
}

/** Delete the vector for a tab (called on tab close or navigation away). */
export async function deleteVector(tabId) {
  await chrome.storage.session.remove(key(tabId));
}
